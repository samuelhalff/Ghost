const scmp = require("scmp");
const zlib = require("zlib");
const crypto = require("crypto");

const digestMethod = "sha1";
const salt = "cookie-session";
const validityTime =
    parseInt(process.env.COOKIES_DURATION_MINUTES || "1440") * 60;
const secret = Buffer.from(process.env.SECRET_KEY || "", "utf8");

if (!secret.byteLength) {
    console.error(
        "SECRET_KEY env variable is not set. Application can't be started"
    );
    throw Error("set SECRET_KEY in env variables to start the app.");
}

function hmacSign(data, key) {
    var hmac = crypto.createHmac(digestMethod, key);
    hmac.update(data);
    return hmac.digest();
}

function applySignature(value) {
    const key = hmacSign(salt, secret);
    const sig = hmacSign(value, key);

    return sig;
}

async function unzipHelper(payload) {
    return await new Promise((resolve, reject) => {
        zlib.unzip(payload, (error, res) => {
            if (error) {
                reject(error.message);
            } else {
                resolve(JSON.parse(res.toString()));
            }
        });
    });
}

module.exports.getUserIdFromCookies = async function getUserIdFromCookies(
    value
) {
    const isZipped = value.startsWith(".");
    const [encodedToken, timestampPart, sig] = value
        .split(".")
        .slice(isZipped ? 1 : 0);

    const timestamp = Buffer.from(timestampPart, "base64").readUInt32BE(0);

    if (Date.now() / 1000 - timestamp > validityTime) {
        throw "Token is not valid anymore";
    }

    const validateString =
        (isZipped ? "." : "") + encodedToken + "." + timestampPart;
    const valid = scmp(
        Buffer.from(sig, "base64"),
        applySignature(validateString)
    );

    if (!valid) {
        throw "Token was tampered with !!!";
    }

    // "." indicates a necessary unzip
    if (isZipped) {
        const res = await unzipHelper(Buffer.from(encodedToken, "base64"));

        if (typeof res == "string") {
            throw `Could not unzip token ${res}`;
        }
        return res._user_id;
    }

    const user_object = JSON.parse(
        Buffer.from(encodedToken, "base64").toString()
    );
    return user_object._user_id;
};