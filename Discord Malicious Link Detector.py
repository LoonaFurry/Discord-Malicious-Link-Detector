import discord
from discord.ext import commands, tasks
import requests
import os

# Replace with your own Discord bot token
TOKEN = 'MTEzMDg5NjA5NTczNjc3MDcwMg.Ge7SfK.UqDHbA0nVqAfpJ4n8NiDma8iAWxQXTuqvxCe8Q'

# Replace with your own VirusTotal API key
VIRUSTOTAL_API_KEY = '8c8369b766b811703c1d73d541dd4de6242984df66a7b961628d3fe771b8c7e5'

# Create the Discord bot
intents = discord.Intents.all()
intents.typing = False
intents.presences = False
bot = commands.Bot(command_prefix='!', intents=intents)

# Dictionary to store the messages to be deleted
messages_to_delete = {}

@bot.event
async def on_message(message):
    # Check if the message contains a link
    if 'http' in message.content:
        # Check the link with VirusTotal API
        url = message.content.split()[0]
        response = requests.get(f'https://www.virustotal.com/vtapi/v2/url/report?apikey={VIRUSTOTAL_API_KEY}&resource={url}')
        data = response.json()

        # If the link is detected as malicious, schedule the message for deletion
        if data['response_code'] == 1 and data['positives'] > 0:
            messages_to_delete[message.id] = message
            await message.channel.send(f'{message.author.mention}, this message will be deleted in 10 seconds and your link is contains a potentially malicious link.')
            delete_message.start(message.id)
        # If the link is detected as safe, provide a warning message
        elif data['response_code'] == 1 and data['positives'] == 0:
            await message.channel.send(f'{message.author.mention}, your message contains a safe link.')

    # Process other commands
    await bot.process_commands(message)

@tasks.loop(seconds=1)
async def delete_message(message_id):
    if message_id in messages_to_delete:
        message = messages_to_delete[message_id]
        await message.delete()
        del messages_to_delete[message_id]
        delete_message.stop()

@bot.event
async def on_ready():
    print(f'{bot.user.name} has connected to Discord!')

bot.run(TOKEN)