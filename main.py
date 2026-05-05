import asyncio
import httpx
from urllib.parse import urlparse, parse_qs

async def main():
    
    async with httpx.AsyncClient() as client:
        response = await client.get('https://raw.githubusercontent.com/btsk161/Freeinternet_byMygalaru.github.io/refs/heads/main/premium.txt')
        # print(response.text.splitlines())
        lines=response.text.splitlines()

        vless_links = clean_vless_links = [line.strip() for line in lines if line.strip().startswith('vless://')]

        print(vless_links)

        for link in vless_links:
            parsed = urlparse(link)
            print("Протокол:", parsed.scheme)   
            print("UUID:", parsed.username) 
            print("IP/Хост:", parsed.hostname) 
            print("Порт:", parsed.port)    
            print("Имя:", parsed.fragment)
            print("-" * 30) 


asyncio.run(main())