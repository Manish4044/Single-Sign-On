const functions = require('firebase-functions');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const rp = require('request-promise');
const { isArray } = require('util');
var serviceAccount = require("./serviceAccount.json");
const AD_CRED = require('./data.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL:'https://IdpKeys.firebaseio.com'
});
const db = admin.firestore();

const cors = require('cors')({ origin: true });

const TENANTID = '08393a0e-7b86-4136-b9c8-ad5f23fc6267';
const issuerURI = `https://sts.windows.net/${TENANTID}/`;

let keys = [];

exports.validateAuth = functions.https.onRequest(async (req, res) => {
    cors(req, res, async () => {
        // After Microsoft Login Return, If error occurs then display
        if (req.query && req.query.error) {
            console.error(`Authentication request error from Azure AD: ${req.query.error_description}. Full details: ${JSON.stringify(req.query)}`);
            res.status(400).send(`Oh oh, something went wrong. Please contact support with the following message: Invalid authentication request: ${req.query.error_description}`);
            return;
        }
        
        // After Microsoft Login Return, If ACCESS_TOKEN is present validate and continue;
        if (req.body && req.body.id_token) {
            try {
                // Extract id_token and application url from request
                const token = req.body.id_token;
                const app_url = req.body.state;

                // Validating id_token
                const unverified = jwt.decode(token, { complete: true });
                if (!unverified || !unverified.payload || unverified.payload.iss !== issuerURI) {
                    console.error(`Invalid unverified token (iss): ${token}. Unverified decoding: ${unverified}`);
                    throw new Error("Invalid issuer");
                }
                if (!unverified.header || unverified.header.alg !== "RS256" || !unverified.header.kid) {
                    throw new Error(`Invalid header or algorithm on token: ${token}`);
                }
                await getSignatureKeys();
                const k = keys;
                const signatureKey = k.find((c => {
                    return c.kid === unverified.header.kid;
                }));
                if (!signatureKey) {
                    throw new Error(`Signature used in token ${token} is not in the list of recognized keys: ${JSON.stringify(k)}`);
                }
                const upn = await verifyToken(token, signatureKey.x5c[0]);

                // Creating custom token with specific identity group
                const props = findCredForUrl(app_url);
                const tenantManager = admin.auth().tenantManager();
                const identityTenantId = props.identityTenantId;
                const tenantAuth = tenantManager.authForTenant(identityTenantId);
                const customToken = await tenantAuth.createCustomToken(upn);

                //Redirecting back to application
                res.cookie('authToken',customToken,{maxAge:5000});
                res.redirect(`${app_url}?identityTenantId=${identityTenantId}`);  
            } catch (err) {
                console.error(`Failed to create custom token: ${err}`);
                res.status(400).send(`Oh oh, something went wrong. Please contact support with the following message: see the logs for more information.`);
            }
        }
        // Initially ACCESS Token will not be present so redirect to login.microsoft.com  
        else {
            const microsoft_login_uri = createLoginURL(req);
            res.redirect(microsoft_login_uri);
        }
    });
});

function createLoginURL(req)
{
    // console.log("Req Query",req.query.login_hint);
    const app_url = req.headers.referer;
    const found = findCredForUrl(app_url);
    const clientId = found.clientId;
    const auth_url = 'http://localhost:5000/queueme-c58c1/us-central1/validateAuth/';
    let login_hint_query = "";
    if(req.query && req.query.login_hint && req.query.login_hint.length !== 0 )
    login_hint_query = "login_hint="+req.query.login_hint;
    const redirect_uri = `https://login.microsoftonline.com/common/oauth2/authorize?client_id=${clientId}&&response_type=id_token&${login_hint_query}&scope=openid&nonce=42&state=${app_url}&response_mode=form_post&redirect_uri=${auth_url}`
    return redirect_uri;
}

function getTenantNameFrom(email){
    // Return the tenant name
    // Example 
    // Email : manish1@9532643074bgmail.onmicrosoft.com
    // TenantName :  9532643074bgmail
}

function checkMicrosoftADEmail(email)
{
    // Make regular expression for .onmicrosoft.com   
}

function findCredForUrl(url)
{
    var found = AD_CRED.find(function (element) {
        return isSameDomain(url,element.domain);
    });
    return found;
}

function isSameDomain(currUrl, targetUrl)
{
    let domain1 = (new URL(currUrl));
    let domain2 = (new URL(targetUrl));
    return domain1.hostname == domain2.hostname && domain1.port == domain2.port;
}

async function getSignatureKeys(){
    if (keys.length !== 0) {
        return keys; 
    }
    keys = await getKeysFromDB();
    if (keys.length !== 0) { // Will be empty the first time.
        return keys;
    }
    return await updateIdpKeys();
}

async function getKeysFromDB(){
    const result = [];
    const querySnapshot = await db.collection("IdpKeys").get();
    querySnapshot.forEach(function (doc) {
        result.push(doc.data());
    });
    return result;
}

async function updateIdpKeys(){
    const data = await rp({ uri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys', json: true });
    if (data && data.keys && isArray(data.keys) && data.keys.length > 0) {
        data.keys.forEach(async (k) => {
            // console.log(k.id," ",k);
            // const docRef = doc(collection(db, "IdpKeys"),k.id);
            // await setDoc(docRef, k);
            // await db.collection('IdpKeys').doc(k.kid).set(k);
        });
        keys = data.keys; // Store in container. Will be re-used when container is re-used
        return keys;
    } else {
        console.error(`Received from MS openID endpoint: ${data}`);
        throw new Error("Could not read the keys from MS' openID discovery endpoint");
    }
}

updateIdpKeys();

async function getOldKeys(updatedKeys) {
    // const querySnapshot = await db.collection("IdpKeys").get();
    const querySnapshot = await getDocs(collection(db,'IdpKeys'));
    const oldKeys = [];
    querySnapshot.forEach(doc => {
        if (!updatedKeys.some(k => k.kid === doc.id)) {
            oldKeys.push(doc.id);
        }
    });
    return oldKeys;
}

async function verifyToken(token, cert, tenant_id) {
    return new Promise((resolve, reject) => {
        // console.log(`Selected signature key: ${cert}`);
        jwt.verify(token, convertCertificate(cert), {
            algorithms: ["RS256"], // Prevent the 'none' alg from being used
            issuer: issuerURI
        }, function (err, decoded) {
            if (err || !decoded) {
                console.error(`Could not verify token: ${err}`);
                reject(err);
            } else {
                const userId = decoded.upn || decoded.unique_name;
                if (!userId) {
                    console.error(`Could not find userId: ${JSON.stringify(decoded)}`);
                    reject("Could not find a userId in the response token");
                }
                // console.info(`logged-in user: ${userId}`);
                resolve(userId);
            }
        })
    });
}

//Certificate must be in this specific format or else jwt's verify function won't accept it
function convertCertificate(originalCert) {
    const beginCert = "-----BEGIN CERTIFICATE-----";
    const endCert = "-----END CERTIFICATE-----";
    let cert = originalCert.replace("\n", "");
    cert = cert.replace(beginCert, "");
    cert = cert.replace(endCert, "");

    let result = beginCert;
    while (cert.length > 0) {

        if (cert.length > 64) {
            result += "\n" + cert.substring(0, 64);
            cert = cert.substring(64, cert.length);
        }
        else {
            result += "\n" + cert;
            cert = "";
        }
    }
    if (result[result.length] !== "\n")
        result += "\n";
    result += endCert + "\n";
    return result;
}