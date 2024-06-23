const Otp = require('./otpModel');
const crypto = require('crypto');

const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const storeOTP = async (email) => {
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes from now

    await Otp.findOneAndUpdate(
        { email },
        { otp, expiresAt },
        { upsert: true, new: true }
    );

    return otp;
};

const verifyOTP = async (email, otp) => {
    const record = await Otp.findOne({ email });
    if (!record) return false;

    if (record.expiresAt < Date.now()) {
        await Otp.deleteOne({ email });
        return false;
    }

    const isValid = record.otp === otp;
    if (isValid) {
        await Otp.deleteOne({ email });
    }
    return isValid;
};

module.exports = { storeOTP, verifyOTP };