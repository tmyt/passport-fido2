'use strict';

const passport = require('passport-strategy')
    , jwkToPem = require('jwk-to-pem')
    , crypto = require('crypto');

class Fido2Strategy extends passport.Strategy{
  constructor(options, verify){
    super();
    if(typeof options === 'function'){
      verify = options;
      options = {};
    }
    this.name = 'fido2';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
    this._readProfile = options.readProfile;
  }
  authenticate(req){
    const id = req.query.id;
    this._readProfile(id, (err, key, profile) => {
      if(err || !key || !profile){
        return this.fail({message: 'Could not find user'}, 400);
      }
      const digest = crypto.createHash('sha256')
        .update(new Buffer(req.query.clientData, 'base64'))
        .digest();
      const verify = crypto.createVerify('RSA-SHA256')
        .update(new Buffer(req.query.authenticatorData, 'base64'))
        .update(digest);
      if(!verify.verify(jwkToPem(key), req.query.signature, 'base64')){
        return this.fail({message: 'Failed verification signature'}, 400);
      }
      const verified = (err, user, info) => {
        if(err) { return this.error(err); }
        if(!user) { return this.fail(info); }
        this.success(user, info);
      }
      try{
        if(this._passReqToCallback){
          this._verify(req, id, profile, verified);
        }else{
          this._verify(id, profile, verified);
        }
      }catch(e){
        return this.error(e);
      }
    });
  }
};

module.exports = Fido2Strategy;
