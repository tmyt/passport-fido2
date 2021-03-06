'use strict';

const {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse
} = require('@simplewebauthn/server');
const passport = require('passport-strategy');

const SessionChallenge = 'passport-fido2-challenge';

class Fido2Strategy extends passport.Strategy {
  constructor(options, verify) {
    super();
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }
    this.name = 'fido2';
    this._options = { ...options };
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
    this._readProfile = options.readProfile;
    this._readPublicKeyForId = options.readPublicKeyForId;
    this._readPublicKeyIdsForUser = options.readPublicKeyIdsForUser;
    this._origin = options.origin;
    this._rpId = this._options.rpId || "passport-fido2"
  }
  authenticate(req) {
    const result = JSON.parse(req.body.result);
    this.assertionResult(req, (err, ret) => {
      if (err) {
        return this.fail({ message: 'Failed to verify signature' });
      }
      const ids = { username: req.body.id, keyId: result.id, newCounter: ret.newCounter };
      this._readProfile(ids, (err, profile) => {
        if (err || !profile) return this.fail({ message: 'Failed to read profile' });
        const verified = (err, user, info) => {
          if (err) { return this.error(err); }
          if (!user) { return this.fail(info); }
          this.success(user, info);
        }
        try {
          if (this._passReqToCallback) {
            this._verify(req, ids, profile, verified);
          } else {
            this._verify(ids, profile, verified);
          }
        } catch (e) {
          return this.error(e);
        }
      });
    });
  }
  /*** Attestation ***/
  attestationOptions(req, callback) {
    const opts = generateAttestationOptions({
      attestationType: this._options.attestationType,
      authenticatorSelection: this._options.authenticatorSelection,
      // excludeCredentials: NOT SUPPORTED
      extensions: this._options.extensions,
      rpID: this._rpId,
      rpName: this._options.rpName || "passport-fido2",
      supportedAlgorithmIDs: this._options.supportedAlgorithmIDs,
      timeout: this._options.timeout || 60 * 1000,
      // userDisplayNmae: NOT SUPPORTED
    })
    req.session[SessionChallenge] = opts.challenge;
    callback(null, opts);
  }
  async attestationResult(req, callback) {
    const challenge = req.session[SessionChallenge];
    delete req.session[SessionChallenge];
    try {
      const verification = await verifyAttestationResponse({
        credential: req.body,
        expectedChallenge: challenge,
        expectedOrigin: this._origin,
        expectedRPID: this._rpId,
      });
      const { verified, attestationInfo } = verification;
      if (!verified) {
        return callback(new Error("Verification failed"), null);
      }
      callback(null, { ...attestationInfo, transport: req.body.transport, id: req.body.id });
    } catch (e) {
      callback(e, null);
    }
  }
  /** Assertion ***/
  assertionOptions(req, id, callback) {
    this._readPublicKeyIdsForUser(id, (err, allowCredentials) => {
      if (err) return callback(err, null);
      const opts = generateAssertionOptions({
        allowCredentials: allowCredentials,
        type: "public-key",
      });
      req.session[SessionChallenge] = opts.challenge;
      callback(null, opts);
    });
  }
  assertionResult(req, callback) {
    const result = JSON.parse(req.body.result);
    const challenge = req.session[SessionChallenge];
    delete req.session[SessionChallenge];
    this._readPublicKeyForId(result.id, async (err, authenticator) => {
      if (err) return callback(err, null);
      try {
        const verification = await verifyAssertionResponse({
          credential: result,
          expectedChallenge: challenge,
          expectedOrigin: this._origin,
          expectedRPID: this._rpId,
          authenticator,
        });
        const { verified, assertionInfo } = verification;
        if (!verified) {
          return callback(new Error("Verification failed"), null);
        }
        callback(null, assertionInfo);
      } catch (err) {
        callback(err, null);
      }
    });
  };
};

module.exports = Fido2Strategy;
