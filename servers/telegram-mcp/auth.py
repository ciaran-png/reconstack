import asyncio
import os
from telethon import TelegramClient

async def main():
    print("=== Telegram MCP Authenticator ===")
    print("This script will generate a 'anon.session' file for the MCP server.")
    
    api_id = input("Enter API ID: ")
    api_hash = input("Enter API Hash: ")
    phone = input("Enter Phone Number (e.g., +1555...): ")
    
    client = TelegramClient('anon', api_id, api_hash)
    
    await client.connect()
    
    if not await client.is_user_authorized():
        await client.send_code_request(phone)
        code = input("Enter the code you received: ")
        try:
            await client.sign_in(phone, code)
        except Exception as e:
            # Handle 2FA if needed
            if 'password' in str(e).lower():
                pw = input("Two-step verification password: ")
                await client.sign_in(password=pw)
            else:
                print(f"Error: {e}")
                return

    print("Successfully authenticated!")
    print("Session file 'anon.session' created.")
    print("You can now run the MCP server.")
    
    # Save creds to .env for the server to use (canonical + legacy aliases)
    with open(".env", "w") as f:
        f.write(f"TELEGRAM_API_ID={api_id}\n")
        f.write(f"TELEGRAM_API_HASH={api_hash}\n")
        f.write(f"TG_API_ID={api_id}\n")
        f.write(f"TG_API_HASH={api_hash}\n")
    print("Created .env file with API credentials.")

if __name__ == '__main__':
    asyncio.run(main())
