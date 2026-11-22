function doGet() {
  return HtmlService
    .createHtmlOutputFromFile('Index')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .setTitle("suprieat28's simple converter")
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

// -------------------------------------
// Account configuration
// -------------------------------------

// Kept at 1000 to avoid the current Apps Script hashing delay. This is suitable
// only for a school/demo project; do not reuse important passwords on this app.
// Existing accounts keep using the iteration count saved in their own records.
const AUTH_ITERATIONS = 1000;
const SESSION_TTL = 21600;
const MAX_LOGIN_ATTEMPTS = 8;
const LOGIN_LOCK_SECONDS = 900;
const EMAIL_CODE_TTL_SECONDS = 600;
const EMAIL_RESEND_COOLDOWN_SECONDS = 60;
const EMAIL_CODE_MAX_ATTEMPTS = 5;


// -------------------------------------
// Registration with email verification
// -------------------------------------

function beginAccountRegistration(username, email, password) {
  username = normalizeUsername_(username);
  email = normalizeEmail_(email);
  validatePassword_(password);

  const properties = PropertiesService.getScriptProperties();
  const key = accountKey_(username);

  if (properties.getProperty(key)) {
    throw new Error('That username is already taken.');
  }

  assertEmailAvailable_(email, username);

  const cache = CacheService.getScriptCache();
  const pendingKey = 'pending-registration:' + username;
  const cooldownKey = 'registration-email-cooldown:' + username;

  if (cache.get(cooldownKey)) {
    throw new Error('Please wait one minute before requesting another code.');
  }

  const salt = Utilities.getUuid() + Utilities.getUuid();
  const code = createEmailCode_();
  const pending = {
    username: username,
    email: email,
    salt: salt,
    passwordHash: passwordHash_(password, salt, AUTH_ITERATIONS),
    iterations: AUTH_ITERATIONS,
    createdAt: new Date().toISOString(),
    codeHash: emailCodeHash_(email, code),
    attempts: 0,
    expiresAt: Date.now() + EMAIL_CODE_TTL_SECONDS * 1000
  };

  cache.put(pendingKey, JSON.stringify(pending), EMAIL_CODE_TTL_SECONDS);
  cache.put(cooldownKey, '1', EMAIL_RESEND_COOLDOWN_SECONDS);

  try {
    sendAccountCodeEmail_(email, code, 'Verify your email address',
      'Use this code to finish creating your suprieat28 simple converter account.');
  } catch (error) {
    cache.remove(pendingKey);
    cache.remove(cooldownKey);
    console.error('Registration email could not be sent: ' + error);
    throw new Error('Could not send the verification email. Check the email address and try again.');
  }

  return { success: true };
}


function resendAccountRegistrationCode(username) {
  username = normalizeUsername_(username);
  const cache = CacheService.getScriptCache();
  const pendingKey = 'pending-registration:' + username;
  const cooldownKey = 'registration-email-cooldown:' + username;
  const raw = cache.get(pendingKey);

  if (!raw) throw new Error('Your registration request expired. Please start again.');
  if (cache.get(cooldownKey)) {
    throw new Error('Please wait one minute before requesting another code.');
  }

  const pending = JSON.parse(raw);
  const code = createEmailCode_();
  pending.codeHash = emailCodeHash_(pending.email, code);
  pending.attempts = 0;
  pending.expiresAt = Date.now() + EMAIL_CODE_TTL_SECONDS * 1000;

  cache.put(pendingKey, JSON.stringify(pending), EMAIL_CODE_TTL_SECONDS);
  cache.put(cooldownKey, '1', EMAIL_RESEND_COOLDOWN_SECONDS);

  try {
    sendAccountCodeEmail_(pending.email, code, 'Your new verification code',
      'Use this new code to finish creating your suprieat28 simple converter account.');
  } catch (error) {
    console.error('Registration resend email could not be sent: ' + error);
    throw new Error('Could not send the verification email. Please try again later.');
  }

  return { success: true };
}


function verifyAccountRegistration(username, code) {
  username = normalizeUsername_(username);
  code = normalizeEmailCode_(code);

  const cache = CacheService.getScriptCache();
  const pendingKey = 'pending-registration:' + username;
  const raw = cache.get(pendingKey);
  if (!raw) throw new Error('Your verification code expired. Please request a new one.');

  const pending = JSON.parse(raw);
  if (Date.now() > Number(pending.expiresAt || 0)) {
    cache.remove(pendingKey);
    throw new Error('Your verification code expired. Please request a new one.');
  }

  if (!constantTimeEqual_(emailCodeHash_(pending.email, code), pending.codeHash)) {
    pending.attempts = Number(pending.attempts || 0) + 1;
    if (pending.attempts >= EMAIL_CODE_MAX_ATTEMPTS) {
      cache.remove(pendingKey);
      throw new Error('Too many incorrect codes. Please start registration again.');
    }
    const remaining = Math.max(1, Math.ceil((pending.expiresAt - Date.now()) / 1000));
    cache.put(pendingKey, JSON.stringify(pending), remaining);
    throw new Error('That verification code is incorrect.');
  }

  const properties = PropertiesService.getScriptProperties();
  const key = accountKey_(username);
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) throw new Error('The account system is busy. Please try again.');

  let record;
  try {
    if (properties.getProperty(key)) throw new Error('That username is already taken.');
    assertEmailAvailable_(pending.email, username);

    record = {
      username: username,
      email: pending.email,
      emailVerified: true,
      salt: pending.salt,
      passwordHash: pending.passwordHash,
      iterations: pending.iterations,
      createdAt: pending.createdAt,
      sessionVersion: 1
    };
    properties.setProperty(key, JSON.stringify(record));
  } finally {
    lock.releaseLock();
  }

  cache.remove(pendingKey);
  cache.remove('registration-email-cooldown:' + username);
  return createSessionResponse_(record);
}


// -------------------------------------
// Login
// -------------------------------------

function loginAccount(username, password) {
  username = normalizeUsername_(username);

  if (typeof password !== 'string' || password.length > 128) {
    throw new Error('Invalid username or password.');
  }

  const cache = CacheService.getScriptCache();
  const attemptKey = 'login-attempts:' + username;
  const attempts = Number(cache.get(attemptKey) || 0);

  if (attempts >= MAX_LOGIN_ATTEMPTS) {
    throw new Error('Too many login attempts. Please try again in 15 minutes.');
  }

  const properties = PropertiesService.getScriptProperties();
  const stored = properties.getProperty(accountKey_(username));
  const record = stored ? JSON.parse(stored) : null;
  const salt = record ? record.salt : 'invalid-account-salt';
  const iterations = record ? Number(record.iterations || AUTH_ITERATIONS) : AUTH_ITERATIONS;

  const candidateHash = passwordHash_(password, salt, iterations);

  if (!record || !constantTimeEqual_(candidateHash, record.passwordHash)) {
    cache.put(attemptKey, String(attempts + 1), LOGIN_LOCK_SECONDS);
    throw new Error('Invalid username or password.');
  }

  cache.remove(attemptKey);
  return createSessionResponse_(record);
}


// -------------------------------------
// Account profile and sessions
// -------------------------------------

function getAccountProfile(sessionToken) {
  const record = requireAuthenticatedUser_(sessionToken);
  return publicUser_(record);
}


function logoutAccount(sessionToken) {
  if (typeof sessionToken === 'string' && sessionToken.length <= 128) {
    CacheService.getScriptCache().remove('auth:' + sessionToken);
  }
  return { success: true };
}


// -------------------------------------
// Verify / change recovery email
// -------------------------------------

function requestAccountEmailVerification(sessionToken, newEmail) {
  const user = requireAuthenticatedUser_(sessionToken);
  newEmail = normalizeEmail_(newEmail);
  assertEmailAvailable_(newEmail, user.username);

  const cache = CacheService.getScriptCache();
  const pendingKey = 'pending-email-change:' + user.username;
  const cooldownKey = 'email-change-cooldown:' + user.username;

  if (cache.get(cooldownKey)) {
    throw new Error('Please wait one minute before requesting another code.');
  }

  const code = createEmailCode_();
  const pending = {
    email: newEmail,
    codeHash: emailCodeHash_(newEmail, code),
    attempts: 0,
    expiresAt: Date.now() + EMAIL_CODE_TTL_SECONDS * 1000
  };

  cache.put(pendingKey, JSON.stringify(pending), EMAIL_CODE_TTL_SECONDS);
  cache.put(cooldownKey, '1', EMAIL_RESEND_COOLDOWN_SECONDS);

  try {
    sendAccountCodeEmail_(newEmail, code, 'Verify your recovery email',
      'Use this code to add this address as the recovery email for your suprieat28 simple converter account.');
  } catch (error) {
    cache.remove(pendingKey);
    cache.remove(cooldownKey);
    console.error('Email-change verification could not be sent: ' + error);
    throw new Error('Could not send the verification email. Check the address and try again.');
  }

  return { success: true };
}


function verifyAccountEmail(sessionToken, code) {
  const user = requireAuthenticatedUser_(sessionToken);
  code = normalizeEmailCode_(code);

  const cache = CacheService.getScriptCache();
  const pendingKey = 'pending-email-change:' + user.username;
  const raw = cache.get(pendingKey);
  if (!raw) throw new Error('Your verification code expired. Request a new one.');

  const pending = JSON.parse(raw);
  if (Date.now() > Number(pending.expiresAt || 0)) {
    cache.remove(pendingKey);
    throw new Error('Your verification code expired. Request a new one.');
  }

  if (!constantTimeEqual_(emailCodeHash_(pending.email, code), pending.codeHash)) {
    pending.attempts = Number(pending.attempts || 0) + 1;
    if (pending.attempts >= EMAIL_CODE_MAX_ATTEMPTS) {
      cache.remove(pendingKey);
      throw new Error('Too many incorrect codes. Request a new one.');
    }
    const remaining = Math.max(1, Math.ceil((pending.expiresAt - Date.now()) / 1000));
    cache.put(pendingKey, JSON.stringify(pending), remaining);
    throw new Error('That verification code is incorrect.');
  }

  const properties = PropertiesService.getScriptProperties();
  const key = accountKey_(user.username);
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) throw new Error('The account system is busy. Please try again.');

  let updated;
  try {
    const stored = properties.getProperty(key);
    if (!stored) throw new Error('Account not found. Please log in again.');
    updated = JSON.parse(stored);
    assertEmailAvailable_(pending.email, user.username);
    updated.email = pending.email;
    updated.emailVerified = true;
    properties.setProperty(key, JSON.stringify(updated));
  } finally {
    lock.releaseLock();
  }

  cache.remove(pendingKey);
  cache.remove('email-change-cooldown:' + user.username);
  return { success: true, email: updated.email, emailVerified: true };
}


// -------------------------------------
// Forgot password / reset code
// -------------------------------------

function requestPasswordReset(username) {
  // Always return the same public response so this endpoint does not reveal
  // whether a username exists or has a verified recovery email.
  let normalized;
  try {
    normalized = normalizeUsername_(username);
  } catch (error) {
    return { success: true };
  }

  const cache = CacheService.getScriptCache();
  const cooldownKey = 'password-reset-cooldown:' + normalized;
  const resetKey = 'password-reset:' + normalized;

  if (cache.get(cooldownKey)) return { success: true };
  cache.put(cooldownKey, '1', EMAIL_RESEND_COOLDOWN_SECONDS);

  const stored = PropertiesService.getScriptProperties().getProperty(accountKey_(normalized));
  if (!stored) return { success: true };

  const record = JSON.parse(stored);
  if (!record.email || record.emailVerified !== true) return { success: true };

  const code = createEmailCode_();
  const pending = {
    email: record.email,
    codeHash: emailCodeHash_(record.email, code),
    attempts: 0,
    expiresAt: Date.now() + EMAIL_CODE_TTL_SECONDS * 1000
  };
  cache.put(resetKey, JSON.stringify(pending), EMAIL_CODE_TTL_SECONDS);

  try {
    sendAccountCodeEmail_(record.email, code, 'Your password reset code',
      'Use this code to reset your suprieat28 simple converter password.');
  } catch (error) {
    cache.remove(resetKey);
    console.error('Password reset email could not be sent: ' + error);
    // Keep the same public response regardless of delivery outcome.
  }

  return { success: true };
}


function resetPasswordWithCode(username, code, newPassword) {
  username = normalizeUsername_(username);
  code = normalizeEmailCode_(code);
  validatePassword_(newPassword);

  const cache = CacheService.getScriptCache();
  const resetKey = 'password-reset:' + username;
  const raw = cache.get(resetKey);
  if (!raw) throw new Error('Your reset code expired or is invalid. Request a new one.');

  const pending = JSON.parse(raw);
  if (Date.now() > Number(pending.expiresAt || 0)) {
    cache.remove(resetKey);
    throw new Error('Your reset code expired. Request a new one.');
  }

  if (!constantTimeEqual_(emailCodeHash_(pending.email, code), pending.codeHash)) {
    pending.attempts = Number(pending.attempts || 0) + 1;
    if (pending.attempts >= EMAIL_CODE_MAX_ATTEMPTS) {
      cache.remove(resetKey);
      throw new Error('Too many incorrect codes. Request a new reset code.');
    }
    const remaining = Math.max(1, Math.ceil((pending.expiresAt - Date.now()) / 1000));
    cache.put(resetKey, JSON.stringify(pending), remaining);
    throw new Error('That reset code is incorrect.');
  }

  const properties = PropertiesService.getScriptProperties();
  const key = accountKey_(username);
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) throw new Error('The account system is busy. Please try again.');

  try {
    const stored = properties.getProperty(key);
    if (!stored) throw new Error('The reset request is no longer valid.');
    const record = JSON.parse(stored);
    if (record.emailVerified !== true || record.email !== pending.email) {
      throw new Error('The recovery email has changed. Request a new reset code.');
    }

    const newSalt = Utilities.getUuid() + Utilities.getUuid();
    record.salt = newSalt;
    record.passwordHash = passwordHash_(newPassword, newSalt, AUTH_ITERATIONS);
    record.iterations = AUTH_ITERATIONS;
    record.sessionVersion = Number(record.sessionVersion || 1) + 1;
    properties.setProperty(key, JSON.stringify(record));
  } finally {
    lock.releaseLock();
  }

  cache.remove(resetKey);
  cache.remove('login-attempts:' + username);
  return { success: true };
}


// -------------------------------------
// Change password while signed in
// -------------------------------------

function changeAccountPassword(sessionToken, currentPassword, newPassword) {
  const user = requireAuthenticatedUser_(sessionToken);
  validatePassword_(newPassword);

  if (typeof currentPassword !== 'string' || currentPassword.length > 128) {
    throw new Error('Your current password is incorrect.');
  }

  const properties = PropertiesService.getScriptProperties();
  const key = accountKey_(user.username);
  let record = JSON.parse(properties.getProperty(key));

  const currentHash = passwordHash_(currentPassword, record.salt, Number(record.iterations || AUTH_ITERATIONS));
  if (!constantTimeEqual_(currentHash, record.passwordHash)) {
    throw new Error('Your current password is incorrect.');
  }

  const newSalt = Utilities.getUuid() + Utilities.getUuid();
  const newHash = passwordHash_(newPassword, newSalt, AUTH_ITERATIONS);
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) throw new Error('The account system is busy. Please try again.');

  try {
    record = JSON.parse(properties.getProperty(key));
    const latestCurrentHash = passwordHash_(currentPassword, record.salt, Number(record.iterations || AUTH_ITERATIONS));
    if (!constantTimeEqual_(latestCurrentHash, record.passwordHash)) {
      throw new Error('Your password has changed. Please log in again.');
    }

    record.salt = newSalt;
    record.passwordHash = newHash;
    record.iterations = AUTH_ITERATIONS;
    record.sessionVersion = Number(record.sessionVersion || 1) + 1;
    properties.setProperty(key, JSON.stringify(record));
  } finally {
    lock.releaseLock();
  }

  return createSessionResponse_(record);
}


// -------------------------------------
// Email / account helpers
// -------------------------------------

function normalizeEmail_(email) {
  if (typeof email !== 'string') throw new Error('Please enter a valid email address.');
  email = email.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    throw new Error('Please enter a valid email address.');
  }
  return email;
}


function normalizeEmailCode_(code) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) {
    throw new Error('Enter the six-digit code from your email.');
  }
  return code.trim();
}


function createEmailCode_() {
  const digits = Utilities.getUuid().replace(/\D/g, '');
  return (digits + '000000').slice(0, 6);
}


function emailCodeHash_(email, code) {
  const digest = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    String(email).toLowerCase() + ':' + String(code),
    Utilities.Charset.UTF_8
  );
  return digest.map(byte => ('0' + (byte & 255).toString(16)).slice(-2)).join('');
}


// Run this once from the Apps Script editor to trigger Google's email permission prompt.
function authorizeEmailSending() {
  return MailApp.getRemainingDailyQuota();
}


function sendAccountCodeEmail_(email, code, subject, description) {
  const body = description + '\n\nYour verification code is: ' + code +
    '\n\nThis code expires in 10 minutes. If you did not request it, you can ignore this email.';
  const htmlBody = '<div style="font-family:Arial,sans-serif;max-width:520px;color:#111">' +
    '<h2 style="font-size:18px">suprieat28\'s simple converter</h2>' +
    '<p>' + escapeHtml_(description) + '</p>' +
    '<p style="font-size:28px;font-weight:bold;letter-spacing:6px">' + code + '</p>' +
    '<p>This code expires in 10 minutes. If you did not request it, ignore this email.</p>' +
    '</div>';
  MailApp.sendEmail({
    to: email,
    subject: subject,
    body: body,
    htmlBody: htmlBody,
    name: "suprieat28's simple converter"
  });
}


function escapeHtml_(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}


function assertEmailAvailable_(email, excludedUsername) {
  const all = PropertiesService.getScriptProperties().getProperties();
  Object.keys(all).forEach(key => {
    if (key.indexOf('account:') !== 0) return;
    try {
      const record = JSON.parse(all[key]);
      if (record.username !== excludedUsername &&
          record.emailVerified === true &&
          String(record.email || '').toLowerCase() === email) {
        throw new Error('That email address is already linked to another account.');
      }
    } catch (error) {
      if (error && error.message === 'That email address is already linked to another account.') throw error;
      // Ignore malformed unrelated account records rather than blocking all registrations.
    }
  });
}


// -------------------------------------
// Existing password / session helpers
// -------------------------------------

function normalizeUsername_(username) {
  if (typeof username !== 'string') throw new Error('Please enter a username.');
  username = username.trim().toLowerCase();
  if (!/^[a-z0-9_-]{3,24}$/.test(username)) {
    throw new Error('Username must be 3–24 characters using letters, numbers or underscores.');
  }
  return username;
}


function validatePassword_(password) {
  if (typeof password !== 'string') throw new Error('Please enter a password.');
  if (password.length < 10) throw new Error('Your password must be at least 10 characters.');
  if (password.length > 128) throw new Error('Your password cannot exceed 128 characters.');
}


function accountKey_(username) {
  return 'account:' + username;
}


function passwordHash_(password, salt, iterations) {
  const passwordBytes = Utilities.newBlob(password).getBytes();
  const saltBytes = Utilities.newBlob(salt).getBytes();
  const firstBlock = Array.from(saltBytes).concat([0, 0, 0, 1]);

  let u = Utilities.computeHmacSha256Signature(firstBlock, passwordBytes);
  let output = Array.from(u, byte => byte & 255);

  for (let i = 1; i < iterations; i++) {
    u = Utilities.computeHmacSha256Signature(u, passwordBytes);
    for (let j = 0; j < output.length; j++) {
      output[j] = output[j] ^ (u[j] & 255);
    }
  }

  return output.map(byte => ('0' + (byte & 255).toString(16)).slice(-2)).join('');
}


function constantTimeEqual_(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return difference === 0;
}


function publicUser_(record) {
  return {
    username: record.username,
    email: record.email || '',
    emailVerified: record.emailVerified === true,
    createdAt: record.createdAt
  };
}


function createSessionResponse_(record) {
  const token = Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
  CacheService.getScriptCache().put(
    'auth:' + token,
    JSON.stringify({
      username: record.username,
      version: Number(record.sessionVersion || 1)
    }),
    SESSION_TTL
  );
  return {
    success: true,
    sessionToken: token,
    user: publicUser_(record)
  };
}


function requireAuthenticatedUser_(sessionToken) {
  if (typeof sessionToken !== 'string' || !/^[a-f0-9]{64}$/i.test(sessionToken)) {
    throw new Error('Your session has expired. Please log in again.');
  }

  const cache = CacheService.getScriptCache();
  const sessionData = cache.get('auth:' + sessionToken);
  if (!sessionData) throw new Error('Your session has expired. Please log in again.');

  const session = JSON.parse(sessionData);
  const stored = PropertiesService.getScriptProperties().getProperty(accountKey_(session.username));
  if (!stored) throw new Error('Account not found. Please log in again.');

  const record = JSON.parse(stored);
  if (Number(record.sessionVersion || 1) !== Number(session.version)) {
    throw new Error('Your session is no longer valid. Please log in again.');
  }
  return record;
}
