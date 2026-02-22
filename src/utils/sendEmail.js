import * as Brevo from "@getbrevo/brevo";
import ApiError from "./ApiError.js"; // adjust path if needed

// Create API instance
const apiInstance = new Brevo.TransactionalEmailsApi();

// Set API key
apiInstance.setApiKey(
  Brevo.TransactionalEmailsApiApiKeys.apiKey,
  process.env.BREVO_API_KEY
);

export const sendEmail = async ({ to, subject, text }) => {
  try {
    await apiInstance.sendTransacEmail({
      sender: {
        name: "Live Polls",
        email: process.env.EMAIL_USER,
      },
      to: [{ email: to }],
      subject,
      textContent: text,
    });

  } catch (error) {
    console.error("Email send failed:", error.response?.body || error.message);
    throw new ApiError(500, "Unable to send email");
  }
};