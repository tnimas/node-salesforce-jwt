var request = require('request');
var jwt = require('jsonwebtoken');

/* Possible endpoint values:

-- Developer/Production Orgs: https://login.salesforce.com

-- Sandbox: https://test.salesforce.com

-- My Domain Enabled: https://domain.instance.my.salesforce.com

-- Base Instance: instance.salesforce.com (e.g. https://cs16.salesforce.com)

*/
module.exports.getToken = function (clientId, privateKey, userName, endpoint, cb) {
	var options = {
		issuer: clientId,
		audience: endpoint,
		expiresIn: '120m',
		algorithm:'RS256'
	}

	var token = jwt.sign({ prn: userName }, privateKey, options);

	var post = {
		uri: endpoint + '/services/oauth2/token',
		form: {
			'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
			'assertion':  token
		},
		method: 'post'
	}

	request(post, function(err, res, body) {
		if (err) {
			cb(err);
			return;
		};

		var reply = JsonTryParse(body);

		if (!reply) {
			cb(new Error('No response from oauth endpoint.'));
			return;
		};

		if (res.statusCode != 200) {
			var message = 'Unable to authenticate: ' + reply.error + ' (' + reply.error_description + ')';
			cb(new Error(message))
			return;
		};

		cb(null, reply.access_token);
	});
}

function JsonTryParse(string) {
	try {
		return JSON.parse(string);
	} catch (e) {
		return null;
	}
}