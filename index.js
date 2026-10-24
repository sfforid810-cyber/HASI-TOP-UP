// Hasi — password reset by mobile number (6-digit code sent by admin on WhatsApp)
// Deploy:  firebase deploy --only functions      (needs the Blaze plan)
const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { initializeApp } = require('firebase-admin/app');
const { getFirestore, Timestamp } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');
const crypto = require('crypto');

initializeApp();
const db = getFirestore();

const OPTS = { region: 'us-central1', cors: true, maxInstances: 10 };
const TTL_MS = 15 * 60 * 1000;     // code valid for 15 minutes
const COOLDOWN_MS = 60 * 1000;     // 1 new code per minute per user
const MAX_TRIES = 5;               // wrong attempts before the code is locked

const digits = (v) => String(v || '').replace(/\D/g, '');
const key10 = (v) => digits(v).slice(-10);

async function findUser(rawPhone) {
  const k = key10(rawPhone);
  if (k.length < 10) return null;
  // 1) fast path: common stored formats
  const variants = [k, '0' + k, '880' + k, '+880' + k, '88' + '0' + k];
  const q = await db.collection('users').where('phone', 'in', variants).limit(1).get();
  if (!q.empty) { const d = q.docs[0]; return { uid: d.id, ...d.data() }; }
  // 2) fallback: formats with spaces / dashes
  const all = await db.collection('users').select('phone', 'email', 'name').get();
  for (const d of all.docs) if (key10(d.get('phone')) === k) return { uid: d.id, ...d.data() };
  return null;
}

function same(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// Loads the active code doc and validates it. Wrong code => counts an attempt.
async function checkCode(phone, code) {
  const user = await findUser(phone);
  if (!user) throw new HttpsError('invalid-argument', 'এই নাম্বারে কোনো অ্যাকাউন্ট পাওয়া যায়নি।');
  const ref = db.collection('resetCodes').doc(user.uid);
  const snap = await ref.get();
  if (!snap.exists || snap.get('status') !== 'active')
    throw new HttpsError('failed-precondition', 'কোডটি আর বৈধ নয়। নতুন কোডের জন্য আবার চেষ্টা করুন।');
  if (snap.get('expiresAt').toMillis() < Date.now())
    throw new HttpsError('deadline-exceeded', 'কোডের মেয়াদ শেষ। নতুন কোড চান।');
  if (!/^\d{6}$/.test(String(code)) || !same(snap.get('code'), code)) {
    const tries = (snap.get('attempts') || 0) + 1;
    await ref.update({ attempts: tries, ...(tries >= MAX_TRIES ? { status: 'locked' } : {}) });
    throw new HttpsError('permission-denied',
      tries >= MAX_TRIES ? 'অনেকবার ভুল হয়েছে, কোড লক হয়ে গেছে। নতুন কোড চান।'
                         : 'কোড ভুল হয়েছে। (আর ' + (MAX_TRIES - tries) + ' বার চেষ্টা করতে পারবেন)');
  }
  return { user, ref };
}

// 1) user taps "Reset" with a mobile number -> a code is created for the admin panel
exports.requestPhoneReset = onCall(OPTS, async (req) => {
  const user = await findUser(req.data && req.data.phone);
  if (!user) throw new HttpsError('invalid-argument', 'এই নাম্বারে কোনো অ্যাকাউন্ট পাওয়া যায়নি।');
  const ref = db.collection('resetCodes').doc(user.uid);
  const old = await ref.get();
  if (old.exists && old.get('status') === 'active' && Date.now() - old.get('createdAt').toMillis() < COOLDOWN_MS)
    throw new HttpsError('resource-exhausted', 'একটু অপেক্ষা করুন, ১ মিনিট পর আবার চেষ্টা করুন।');
  const now = Date.now();
  await ref.set({
    uid: user.uid, name: user.name || '', email: user.email || '', phone: digits(req.data.phone),
    code: String(crypto.randomInt(100000, 1000000)),
    status: 'active', attempts: 0,
    createdAt: Timestamp.fromMillis(now), expiresAt: Timestamp.fromMillis(now + TTL_MS),
  });
  return { ok: true };                       // the code is NOT returned — only the admin sees it
});

// 2) user types the code the admin sent
exports.verifyResetCode = onCall(OPTS, async (req) => {
  await checkCode(req.data && req.data.phone, req.data && req.data.code);
  return { ok: true };
});

// 3) user sets a new password
exports.redeemResetCode = onCall(OPTS, async (req) => {
  const { phone, code, newPassword } = req.data || {};
  if (typeof newPassword !== 'string' || newPassword.length < 6)
    throw new HttpsError('invalid-argument', 'পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে।');
  const { user, ref } = await checkCode(phone, code);
  await getAuth().updateUser(user.uid, { password: newPassword });
  await getAuth().revokeRefreshTokens(user.uid);          // log out old sessions
  await ref.update({ status: 'used', usedAt: Timestamp.now() });
  return { ok: true, email: user.email || '' };
});
