
export interface Env {
	TELEGRAM_TOKEN: string;
	GEMINI_API_KEY: string;
	DB: D1Database;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		if (request.method === "POST") {
			try {
				const update: any = await request.json();
				if (update.message && update.message.text) {
					const chatId = update.message.chat.id;
					const userText = update.message.text;

					console.log(`Received message: ${userText} from chat: ${chatId}`);

					// --- Step 1: Fetch Context History ---
					const history = await env.DB.prepare(
						"SELECT role, content FROM messages WHERE chat_id = ? ORDER BY created_at ASC LIMIT 10"
					).bind(chatId).all();

					const contents = [];
					if (history.results && history.results.length > 0) {
						for (const msg of history.results) {
							contents.push({
								role: msg.role === 'user' ? 'user' : 'model',
								parts: [{ text: msg.content as string }]
							});
						}
					}

					// Add current user message
					contents.push({
						role: "user",
						parts: [{ text: userText }]
					});

					const geminiUrl = `https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=${env.GEMINI_API_KEY}`;
					const payload = { contents: contents };

					console.log("Sending payload to Gemini with history:", JSON.stringify(payload));

					const geminiResponse = await fetch(geminiUrl, {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify(payload)
					});

					const responseText = await geminiResponse.text();
					console.log(`Gemini raw response status: ${geminiResponse.status}`);
					console.log("Gemini raw response body:", responseText);

					let replyText = "Error communicating with Gemini.";

					if (geminiResponse.ok) {
						try {
							const data = JSON.parse(responseText);
							if (data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts && data.candidates[0].content.parts[0]) {
								replyText = data.candidates[0].content.parts[0].text;
							} else {
								replyText = "Gemini returned an unexpected structure.";
								console.error("Unexpected structure:", data);
							}
						} catch (parseError) {
							console.error("Error parsing Gemini JSON:", parseError);
							replyText = "Error parsing Gemini response.";
						}
					} else {
						replyText = `Gemini API Error: ${geminiResponse.status} - ${responseText}`;
					}

					// --- Step 2: Save Messages to DB ---
					// Verify result is OK before saving to avoid polluting DB with error messages?
					// For now, saving everything as requested.

					// Save User Message
					await env.DB.prepare(
						"INSERT INTO messages (chat_id, role, content) VALUES (?, ?, ?)"
					).bind(chatId, 'user', userText).run();

					// Save Model Response
					// Only save if we got a real reply, or even if error? User asked to save "AI's response".
					// Let's save the replyText.
					await env.DB.prepare(
						"INSERT INTO messages (chat_id, role, content) VALUES (?, ?, ?)"
					).bind(chatId, 'model', replyText).run();


					const telegramUrl = `https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`;
					await fetch(telegramUrl, {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({
							chat_id: chatId,
							text: replyText
						})
					});
				}
			} catch (e) {
				console.error("Error in worker:", e);
			}
		}
		return new Response("OK");
	},
};
