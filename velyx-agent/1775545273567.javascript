const Discord = require('discord.js');
const client = new Discord.Client();
const config = require('./utils/config');
const commandHandler = require('./utils/commandHandler');

client.on('ready', () => {
    console.log('Bot is online');
});

client.on('message', (message) => {
    if (message.author.bot) return;

    const args = message.content.slice(config.prefix).trim().split(/ +/g);
    const commandName = args.shift().toLowerCase();

    commandHandler.execute(message, args, commandName);
});

client.login(config.token);
