'use strict';

const crypto = require('crypto');

module.exports = function(hmacSecret){
  const c = crypto.createHash('sha256')
    .update(`${Date.now()}`).digest('hex');
  const cs = crypto.createHmac('sha256', hmacSecret)
    .update(c).digest('hex');
  return {c, cs};
};
