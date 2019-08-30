'use strict';

const { Fido2Lib } = require('fido2-lib')
    , passport = require('passport-strategy')
    , jwkToPem = require('jwk-to-pem')
    , crypto = require('crypto');

const SessionChallenge = 'passport-fido2-challenge';

class Fido2Strategy extends passport.Strategy{
  constructor(options, verify){
    super();
    if(typeof options === 'function'){
      verify = options;
      options = {};
    }
    this.name = 'fido2';
    this._f2l = new Fido2Lib({
      timeout: options.timeout || 60 * 1000,
      rpId: options.rpId || "passport-fido2",
      rpName: options.rpName || "passport-fido2",
      rpIcon: options.rpIcon || "",
      challengeSize: options.challengeSize || 128,
      attestation: options.attestation || "direct",
      cryptoParams: options.cryptoParams || [-7, -257],
      authenticatorAttachment: options.authenticatorAttachment || "platform",
      authenticatorRequireResidentKey: options.authenticatorRequireResidentKey || false,
      authenticatorUserVerification: options.authenticatorUserVerification || "required"
    });
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
    this._readProfile = options.readProfile;
    this._readPublicKeyForId = options.readPublicKeyForId;
    this._readPublicKeyIdsForUser = options.readPublicKeyIdsForUser;
    this._hmacSecret = options.hmacSecret;
    this._origin = options.origin;
  }
  authenticate(req){
    const id = req.body.id;
    this.assertionResult(req, (err, ret) => {
      if(err){
        return this.fail({message: 'Failed to verify signature'});
      }
      this._readProfile(id, (profile) => {
        if(!profile) return this.fail({message: 'Failed to read profile'});
        const verified = (err, user, info) => {
          if(err) { return this.error(err); }
          if(!user) { return this.fail(info); }
          this.success(user, info);
        }
        try{
          if(this._passReqToCallback){
            this._verify(req, ret.request.id, profile, verified);
          }else{
            this._verify(id, profile, verified);
          }
        }catch(e){
          return this.error(e);
        }
      });
    });
  }
  /*** Attestation ***/
  attestationOptions(req, callback){
     this._f2l.attestationOptions()
     .then(opts => {
       opts.challenge = Array.from(new Uint8Array(opts.challenge));
       req.session[SessionChallenge] = opts.challenge;
       callback(null, opts);
     })
     .catch(err => {
       callback(err, null);
     });
  }
  attestationResult(req, callback){
    const result = JSON.parse(req.body.result);
    const obj = {
      id: result.id,
      rawId: new Uint8Array(result.rawId).buffer,
      response: {
        attestationObject: new Uint8Array(result.response.attestationObject).buffer,
        clientDataJSON: new Uint8Array(result.response.clientDataJSON).buffer,
      },
    };
    const challenge = req.session[SessionChallenge];
    delete req.session[SessionChallenge];
    this._f2l.attestationResult(obj, {
      challenge,
      origin: this._origin,
      factor: 'either',
    })
    .then(opts => {
      callback(null, opts);
    })
    .catch(err => {
      callback(err, null);
    });
  }
  /** Assertion ***/
  assertionOptions(req, id, callback){
    this._readPublicKeyIdsForUser(id, (err, allowCredentials) => {
      if(err) return callback(err, null);
      this._f2l.assertionOptions()
      .then(opts => {
        opts.allowCredentials = allowCredentials;
        opts.challenge = Array.from(new Uint8Array(opts.challenge));
        req.session[SessionChallenge] = opts.challenge;
        callback(null, opts);
      })
      .catch(err => callback(err, null));
    });
  }
  assertionResult(req, callback){
    const result = JSON.parse(req.body.result);
    const obj = {
      id: result.id,
      rawId: new Uint8Array(result.rawId).buffer,
      response: {
        authenticatorData: new Uint8Array(result.response.authenticatorData).buffer,
        clientDataJSON: new Uint8Array(result.response.clientDataJSON).buffer,
        signature: new Uint8Array(result.response.signature).buffer,
        userHandle: new Uint8Array(result.response.userHandle).buffer,
      },
    };
    const challenge = req.session[SessionChallenge];
    delete req.session[SessionChallenge];
    const userHandle = this.base64Encode(req.body.id);
    this._readPublicKeyForId(obj.id, (err, pem) => {
      if(err) return callback(err, null);
      this._f2l.assertionResult(obj, {
        challenge,
        origin: this._origin,
        factor: 'either',
        publicKey: pem,
        prevCounter: 0,
        userHandle,
      })
      .then(ret => callback(null, ret))
      .catch(err => callback(err, null));
    });
  };
  /*** Util **/
  base64Encode(value){
    return new Buffer(value).toString('base64').replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");
  }
};

module.exports = Fido2Strategy;
