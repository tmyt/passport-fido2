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
  readProfile: (id, callback) => {
    fs.readFile(`./keys/${id}.profile`, (err, data) => {
      if(err) return callback(err, null, null);
      try { data = JSON.parse(data); } catch(e) { return callback(e, null, null); }
      callback(null, data.key, data.profile);
    });
  }
},
function(id, profile, done){
  process.nextTick(function(){
    return done(null, profile);
  });
});
```

### Authenticate Requests

```js
app.get('/auth/fido2',
  passport.authenticate('fido2'));

app.get('/auth/line/callback',
  passport.authenticate('fido2', { failureRedirect: '/login', successRedirect: '/' }));

```

### Generate challenge

```js
app.get('/auth/fido2/challenge',
  (req, res) => res.send(Fido2Strategy.challenge('hmac-secret')));

```

## Options

- passReqToCallback (optional): Pass req object to callback
- readProfile (required): function(id, callback(err, pubKey, profile)). you need load public key from your storage.

## Note

Web service must send these authentication parameters via Query String.

- id
- clientData
- authenticatorData
- signature

And you may send these params (server generated challenges).

- c
- cs

## License

[The MIT License](http://opensource.org/licenses/MIT)
