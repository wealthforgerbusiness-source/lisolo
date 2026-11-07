'use strict';

const crypto = require('crypto');
const express = require('express');

const API = 'https://api.saspay.me/api/v1';
const HOUR = 3600000;

function createPay(ctx) {
  const { app, db, userRef, userCache, adminCache, bump, requireAuth, limiter, byUser, wrap, fail, HttpError, baseUrl, body, ID_RE, DAY } = ctx;

  const rawAmount = Number(process.env.PREMIUM_AMOUNT || '2');
  const amountNum = Number.isFinite(rawAmount) && rawAmount > 0 ? rawAmount : 2;
  const currency = (String(process.env.PREMIUM_CURRENCY || 'USD').trim().toUpperCase().slice(0, 3)) || 'USD';
  const daysRaw = parseInt(process.env.PREMIUM_DAYS || '30', 10);
  const days = Number.isInteger(daysRaw) && daysRaw >= 1 && daysRaw <= 3650 ? daysRaw : 30;
  const country = process.env.PAY_COUNTRY === undefined ? 'CD' : String(process.env.PAY_COUNTRY).trim().toUpperCase().slice(0, 2);
  const amount = amountNum.toFixed(2);
  const symbol = currency === 'USD' ? '$' : currency === 'EUR' ? '€' : currency;
  const period = days === 30 ? 'par mois' : days === 365 ? 'par an' : 'pour ' + days + ' jours';
  const label = amountNum.toLocaleString('fr-FR', { maximumFractionDigits: 2 }) + ' ' + symbol + ' ' + period;
  const price = { amount, currency, days, label };

  const payments = () => db.collection('payments');
  const dayOf = (t) => new Date(t + HOUR).toISOString().slice(0, 10);
  const TX_RE = /^[A-Za-z0-9-]{8,64}$/;

  async function sas(path, opts) {
    opts = opts || {};
    const key = process.env.SASPAY_SECRET_KEY;
    if (!key) throw new HttpError(503, 'payment_unavailable');
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), opts.timeout || 15000);
    let res;
    try {
      res = await fetch(API + path, {
        method: opts.method || 'GET',
        headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
        signal: ctl.signal,
      });
    } catch (e) {
      throw new HttpError(502, 'payment_unreachable');
    } finally {
      clearTimeout(timer);
    }
    let json = null;
    try {
      json = await res.json();
    } catch (e) {
      json = null;
    }
    if (!res.ok || !json || json.success === false) {
      console.error('[saspay]', opts.method || 'GET', path, res.status, JSON.stringify((json && json.error) || json).slice(0, 300));
      throw new HttpError(502, 'payment_failed');
    }
    return json.data !== undefined ? json.data : json;
  }

  async function settleOrder(orderId, txId, netAmount) {
    const oref = payments().doc(orderId);
    const out = await db.runTransaction(async (tx) => {
      const os = await tx.get(oref);
      if (!os.exists) return null;
      const o = os.data();
      if (o.status === 'paid') return { already: true, uid: o.uid };
      const now = Date.now();
      const us = await tx.get(userRef(o.uid));
      if (us.exists) {
        const cur = Number(us.data().planExpiresAt || 0);
        tx.update(userRef(o.uid), { plan: 'premium', planExpiresAt: Math.max(now, cur) + o.days * DAY });
      }
      tx.update(oref, { status: 'paid', paidAt: now, txId: String(txId), netAmount: netAmount !== undefined ? String(netAmount) : null, orphan: !us.exists });
      return { already: false, uid: o.uid, amount: Number(o.amount), currency: o.currency };
    });
    if (out && !out.already) {
      userCache.del(out.uid);
      adminCache.del('stats');
      if (out.currency === currency) bump('revenue', out.amount);
    }
    return out;
  }

  async function checkOrder(orderId, o, timeout) {
    const st = await sas('/checkout-sessions/' + encodeURIComponent(o.sessionId) + '/status/', { timeout });
    const tx = String(st.transaction_status || '').toUpperCase();
    if (tx === 'SUCCESS' && st.transaction_id && TX_RE.test(String(st.transaction_id))) {
      await settleOrder(orderId, st.transaction_id);
      return 'paid';
    }
    if (tx === 'FAILED') return 'failed';
    return 'pending';
  }

  function validSignature(raw, ts, sig, secret) {
    const t = Number(ts);
    if (!Number.isFinite(t) || Math.abs(Date.now() / 1000 - t) > 300) return false;
    const expected = crypto.createHmac('sha256', secret).update(ts + '.').update(raw).digest('hex');
    const a = Buffer.from(String(sig).trim().toLowerCase(), 'utf8');
    const b = Buffer.from(expected, 'utf8');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  async function matchOrder(d) {
    const txId = String(d.id);
    const byTx = await payments().where('txId', '==', txId).limit(1).get();
    if (!byTx.empty) return null;
    const cur = String(d.currency || currency).toUpperCase();
    const amt = Number(d.amount);
    const now = Date.now();
    const snap = await payments().where('status', '==', 'pending').where('day', 'in', [dayOf(now), dayOf(now - DAY)]).limit(200).get();
    const cands = snap.docs
      .filter((x) => {
        const o = x.data();
        return o.currency === cur && now - o.createdAt < 6 * HOUR && (!Number.isFinite(amt) || Math.abs(Number(o.amount) - amt) < 0.005);
      })
      .sort((a, b) => b.data().createdAt - a.data().createdAt)
      .slice(0, 10);
    for (const c of cands) {
      const st = await sas('/checkout-sessions/' + encodeURIComponent(c.data().sessionId) + '/status/', { timeout: 6000 });
      if (String(st.transaction_id || '') === txId && String(st.transaction_status || '').toUpperCase() === 'SUCCESS') {
        await settleOrder(c.id, txId, d.net_amount);
        return c.id;
      }
    }
    return null;
  }

  function mountWebhook() {
    app.post(
      '/api/webhooks/saspay',
      limiter(60000, 120),
      express.raw({ type: () => true, limit: '100kb' }),
      wrap(async (req, res) => {
        const secret = process.env.SASPAY_WEBHOOK_SECRET;
        if (!secret) return res.status(503).json({ error: 'not_configured' });
        const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
        const ts = String(req.get('x-webhook-timestamp') || '');
        const sig = String(req.get('x-webhook-signature') || '');
        if (!validSignature(raw, ts, sig, secret)) return res.status(403).json({ error: 'invalid_signature' });
        let evt = null;
        try {
          evt = JSON.parse(raw.toString('utf8'));
        } catch (e) {
          return res.status(400).json({ error: 'bad_json' });
        }
        const d = evt && evt.data;
        if (!evt || evt.event !== 'transaction.success' || !d || !TX_RE.test(String(d.id || ''))) return res.json({ ok: true, ignored: true });
        if (d.type && d.type !== 'PAIEMENT') return res.json({ ok: true, ignored: true });
        const matched = await matchOrder(d);
        return res.json({ ok: true, matched: !!matched });
      })
    );
  }

  function mountRoutes() {
    app.post(
      '/api/pay/init',
      limiter(60000, 20),
      requireAuth,
      byUser(10 * 60000, 8),
      wrap(async (req, res) => {
        if (!process.env.SASPAY_SECRET_KEY) fail(503, 'payment_unavailable');
        const u = req.user;
        const now = Date.now();
        const open = await payments().where('uid', '==', u.uid).where('status', '==', 'pending').limit(25).get();
        let reuse = null;
        open.docs.forEach((d) => {
          const o = d.data();
          if (o.checkoutUrl && now - o.createdAt < 20 * 60000 && o.amount === amount && o.currency === currency && (!reuse || o.createdAt > reuse.createdAt)) {
            reuse = { id: d.id, url: o.checkoutUrl, createdAt: o.createdAt };
          }
        });
        if (reuse) return res.json({ url: reuse.url, orderId: reuse.id });
        const oref = payments().doc();
        const session = {
          amount,
          currency,
          description: 'Lisolo Premium - ' + days + ' jours',
          customer_email: u.email,
          customer_name: u.displayName || u.username || 'Client Lisolo',
          return_url: baseUrl(req) + '/app?pay=' + oref.id + '#profile',
          metadata: { orderId: oref.id, uid: u.uid },
        };
        if (country) session.country = country;
        const s = await sas('/checkout-sessions/', { method: 'POST', body: session });
        const url = String(s.checkout_url || '');
        if (!s.id || !/^https:\/\//i.test(url)) throw new HttpError(502, 'payment_failed');
        await oref.set({
          uid: u.uid,
          email: u.email,
          amount,
          currency,
          days,
          sessionId: String(s.id),
          slug: String(s.slug || ''),
          checkoutUrl: url,
          status: 'pending',
          day: dayOf(now),
          createdAt: now,
          txId: null,
        });
        return res.json({ url, orderId: oref.id });
      })
    );

    app.post(
      '/api/pay/confirm',
      limiter(60000, 60),
      requireAuth,
      byUser(10 * 60000, 40),
      wrap(async (req, res) => {
        const id = String(body(req).orderId || '');
        if (!ID_RE.test(id)) fail(404, 'not_found');
        const s = await payments().doc(id).get();
        if (!s.exists || s.data().uid !== req.user.uid) fail(404, 'not_found');
        const o = s.data();
        if (o.status === 'paid') return res.json({ status: 'paid' });
        const status = await checkOrder(id, o, 10000);
        return res.json({ status });
      })
    );
  }

  return { price, mountWebhook, mountRoutes };
}

module.exports = createPay;
