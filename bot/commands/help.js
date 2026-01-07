const { InlineKeyboard } = require('grammy');
const { isAdmin, getUser } = require('../db/db');
const config = require('../config');
const { section, emphasize, tipLine, escapeMarkdown } = require('../utils/messageStyle');

module.exports = (bot) => {
    bot.command('help', async (ctx) => {
        try {
            const user = await new Promise(r => getUser(ctx.from.id, r));
            const isAuthorized = Boolean(user);
            const isOwner = isAuthorized ? await new Promise(r => isAdmin(ctx.from.id, r)) : false;

            const callList = [
                '📞 /call — launch a fresh voice session (requires access)',
                '🔍 /search <term> — locate calls by number, intent, or ID',
                '🕒 /recent [limit] — list recent calls (max 50)',
                '⏱️ /latency <callSid> — see STT/GPT/TTS timing',
                '🧭 /version — view API/service version info'
            ];

            const smsList = [
                '💬 /sms — send a quick AI-powered SMS (requires access)',
                '📅 /schedulesms — schedule an SMS in the future (requires access)',
                '🧾 /smsconversation <phone> — view recent SMS threads (admin)',
                '🔎 /smsstatus <message_sid> — delivery status for a message (requires access)'
            ];

            const infoList = [
                '🩺 /health or /ping — check bot & API health',
                '📰 /digest — 24h notifications + recent calls digest',
                '📚 /guide — view the master user guide (access required)',
                '📋 /menu — reopen quick actions (access required)',
                '❓ /help — show this message again'
            ];

            const quickUsage = [
                'Use /call or the 📞 button to get started',
                'Enter phone numbers in E.164 format (+1234567890)',
                'Describe the AI agent personality and first message',
                'Monitor live updates and ask for transcripts',
                'End the call with the ✋ Interrupt or ⏹️ End button if needed'
            ];

            const exampleUsage = [
                '+1234567890 (not 123-456-7890)',
                '/search refund',
                '/recent 20',
                '/health'
            ];

            const supportBlock = [
                tipLine('🆘', 'Contact admin: @' + escapeMarkdown(config.admin.username)),
                tipLine('🧭', 'Bot edition: v2.0.0 — secrets aged to perfection')
            ];

            const helpSections = [
                emphasize('Ready to guide your AI calls with sparkling clarity.'),
                section('Call Tools', callList),
                section('SMS Tools', smsList),
                section('Navigation & Info', infoList),
                section('Quick Usage Flow', quickUsage.map(line => `• ${line}`))
            ];

            if (isOwner) {
                const adminList = [
                    '🛡️ /adduser — add a trusted operator',
                    '⭐ /promote — elevate a teammate to admin',
                    '❌ /removeuser — cut access cleanly',
                    '👥 /users — list all authorized personnel',
                    '📣 /bulksms — broadcast smart SMS',
                    '📥 /recentsms [limit] — list recent SMS messages',
                    '📊 /smsstats — view SMS health & delivery',
                    '🧪 /status — deep system status',
                    '🧪 /testapi — hit the API health endpoint',
                    '🧰 /templates — manage reusable prompts',
                    '🍃 /persona — sculpt adaptive agents',
                    '🔀 /provider — view or switch voice providers',
                    '🧭 /version — service version snapshot'
                ];
                helpSections.push(section('Admin Toolkit', adminList));
            }

            helpSections.push(
                section('Examples', exampleUsage.map(line => `• ${line}`)),
                section('Support & Info', supportBlock)
            );

            const unauthSections = [
                emphasize('Welcome! Access is required to use most commands.'),
                section('What this bot can do', [
                    '🤖 Run AI-powered voice calls and SMS outreach',
                    '🧾 Track conversations and delivery status',
                    '🛡️ Admins manage users, templates, and providers'
                ]),
                section('Get access', [
                    tipLine('🆘', `Contact admin: @${escapeMarkdown(config.admin.username)}`),
                    'Share your Telegram @ and reason to be approved.',
                    'Once approved, use /start to see your menu.'
                ])
            ];

            const helpText = isAuthorized ? helpSections.join('\n\n') : unauthSections.join('\n\n');

            const adminUsername = (config.admin.username || '').replace(/^@/, '');

            const kb = isAuthorized
                ? (() => {
                    const keyboard = new InlineKeyboard()
                        .text('📞 New Call', 'CALL')
                        .text('📋 Menu', 'MENU')
                        .row()
                        .text('💬 New Sms', 'SMS')
                        .text('📚 Full Guide', 'GUIDE');

                    if (isOwner) {
                        keyboard.row()
                            .text('👥 Users', 'USERS')
                            .text('➕ Add User', 'ADDUSER')
                            .row()
                            .text('☎️ Provider', 'PROVIDER_STATUS');
                    }
                    return keyboard;
                })()
                : new InlineKeyboard().url('📱 Contact Admin', `https://t.me/${adminUsername}`);

            await ctx.reply(helpText, {
                parse_mode: 'Markdown',
                reply_markup: kb
            });

        } catch (error) {
            console.error('Help command error:', error);
            await ctx.reply('❌ Error displaying help. Please try again.');
        }
    });
};
