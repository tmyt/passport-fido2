# Passport-FIDO2

**THIS IS BETA**

[Passport](http://passportjs.org/) strategy for authenticating with FIDO 2.0.

## Install

```
$ npm install passport-fido2
```

## Usage

### Configure Strategy

```
passport.use(new Fido2Strategy({
  origin: 'https://example.com',
  readProfile: (req, callback) => {
    /* req: {
     *   username: string,
     *   keyId: string,
     * }
     * callback: (Error, Profile) -> void
     */
    fs.readFile(`./keys/${req.keyId}.profile`, (err, data) => {
      if(err) return callback(err, null);
      try { data = JSON.parse(data); } catch(e) { return callback(e, null); }
      callback(null, data);
    });
  },
  readPublicKeyIdsForUser: (username, callback) => {
    const ids = [1, 2, 3];
    callback(null, ids.map(id => ({
      id, type: 'public-key', transports: [ 'internal' ],
    })));
  },
  readPublicKeyForId: (id, callback) => {
    const key = 'pem';
    callback(null, key);
  },
},
function(ids, profile, done){
  process.nextTick(function(){
    return done(null, profile);
  });
});
```

### Authenticate Requests

```js
app.post('/auth/fido2',
  passport.authenticate('fido2'));
app.post('/auth/fido2/callback',
  passport.authenticate('fido2', { failureRedirect: '/login', successRedirect: '/' }));
app.get('/auth/fido2/get', (req, res) => {
  const username = req.query.username;
  stragegy.assertionOptions(req, username, (err, opts) => {
    if(err) return res.status(500).send(err);
    res.send(opts);
  });
});
app.get('/auth/fido2/create', (req, res) => {
  const username = req.query.username; 
  strategy.attestationOptions(req, (err, opts) => {
    opts.user = {
      displayName: username,
      id: username,
      name: username,
      icon: 'https://example.com/example.png',
    };
    res.send(opts);
  });
});
app.get('/auth/fido2/register', (req, res) => {
  try{
    strategy.attestationResult(req, (err, result) => {
      if(err) return res.status(500).send(err);
      res.sendStatus(200);
    });
  }catch(e){
    res.sendStatus(500);
  }
});

```

## Options

- passReqToCallback (optional): Pass req object to callback (default: false).
- readProfile (required): function(ids, callback(err, profile)). Read profile related to ids. `ids: { keyId: string, username: string }`.
- readPublicKeyForId (required): function(keyId, callback(err, keyString)). Read public-key for keyId.
- readPublicKeyIdsForUser (required): function(username, callback(err, keys)). Read public-key ids for username. `keys: Array of { id: 'keyid', type: 'public-key', transports: [ 'internal' ] }`.
- origin (required): Webauthn origin.
- timeout (optional): Webauthn timeout (default: 6000).
- rpId (optional): Webauthn rpId (default: "passport-fido2").
- rpName (optional): Webauthn rpName (default: "passport-fido2").
- rpIcon (optional): Webauthn rpIcon (default: "").
- challengeSize (optional): Webauthn challengeSize (default: 128).
- attestation (optional): Webauthn attestation (default: "direct").
- cryptParams (optional): Webauthn cryptoParams (default: [-7, -257]).
- authenticatorAttachment (optional): Webauthn authenticatorAttachment (default: "platform").
- authenticatorRequiredResidentKey (optional): Webauthn authenticatorRequireResidentKey (default: false).
- authenticatorUserVerification (optional): Webauthn authenticatorUserVerification (default: "required").

## Note

Web service need to send these parameters via request body for `passport.authenticate('fido2')` endpoint.

- keyId (required)
- username (optional)

## License

[The MIT License](http://opensource.org/licenses/MIT)
