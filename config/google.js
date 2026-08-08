import { google } from "googleapis";
import dotenv from "dotenv";

dotenv.config();

const googleClient = new google.auth.OAuth2(
    process.env.GOOGLE_AUTH_CLIENT_ID,
    process.env.GOOGLE_AUTH_SECRET,
    process.env.GOOGLE_CALLBACK_URL
);

export default googleClient;