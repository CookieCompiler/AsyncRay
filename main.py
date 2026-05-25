import asyncio
import httpx
from urllib.parse import urlparse, parse_qs
import json
import os
import time
import base64
import sys


XRAY_BIN = 'xray.exe' if sys.platform == 'win32' else './xray'

async def check_xray(sem, link, index):
    async with sem:
        
        local_port = 10800 + index       
        config_file = f"data_{index}.json" 
        try:
            
            if link.startswith('vmess://'):
                vm=link[8:]
                vme=base64.b64decode(vm + '=' * (-len(vm) % 4)).decode('utf-8')

                v_data = json.loads(vme)
                sid = ""
                pbk = ""
                prot='vmess'
                hosa = v_data.get('add')
                use = v_data.get('id')
                port = int(v_data.get('port'))

                net = v_data.get('net', 'tcp') 
                path = v_data.get('path', '/') 
                sni = v_data.get('sni', '')
                host_header = sni

                fp = v_data.get('fp', 'chrome')
                flow = ""

                sec = "tls" if v_data.get('tls') == 'tls' else "none"

            


            elif link.startswith(('vless://', 'trojan://', 'ss://')):
                parsed = urlparse(link)
                params = parse_qs(parsed.query)

                prot = parsed.scheme
                use = parsed.username
                hosa = parsed.hostname
                port = parsed.port if parsed.port else 443
                nam = parsed.fragment

                net = params.get('type', ['tcp'])[0]
                sec = params.get('security', ['none'])[0]
                sni = params.get('sni', [hosa])[0]

                path = params.get('path', ['/'])[0] 
                pbk = params.get('pbk', [''])[0]    
                sid = params.get('sid', [''])[0]    
                host_header = params.get('host', [sni])[0] 


                fp = params.get('fp', ['chrome'])[0] 
                flow = params.get('flow', [''])[0]



                if prot == 'ss':
                    fp = ""
                    flow = ""
                    net = 'tcp'
                    sec = 'none'
                    path = '/'
                    sni = ''
                    pbk = ""
                    sid = ""
                    host_header = ""
                    try:

                        decoded = base64.b64decode(use + '=' * (-len(vm) % 4)).decode('utf-8')

                        method, password = decoded.split(':', 1)
                    except:
                        method, password = use.split(':', 1)

            stream_settings = {
                "network": net, 
                "security": sec
                }

            if sec == "tls":
                stream_settings["tlsSettings"] = {
                "serverName": sni,
                "allowInsecure": True,
                "fingerprint": fp
                }
            elif sec == "reality":
                stream_settings["realitySettings"] = {
                "serverName": sni,
                "publicKey": pbk,
                "shortId": sid,
                "fingerprint": fp
                }

            if net == "ws":
                stream_settings["wsSettings"] = {
                "path": path,
                "headers": {"Host": host_header}
                }
            elif net == "grpc":
                stream_settings["grpcSettings"] = {
                "serviceName": params.get('serviceName', [''])[0],
                "multiMode": False
                }
            
            elif net == "xhttp":
                stream_settings["xhttpSettings"] = {
                "path": path,
                "host": host_header,
                "mode": params.get('mode', ['auto'])[0]
                }

            outbound_settings = {}
            if prot == 'vless':
                user_config = {"id": use, "encryption": "none"}
                if flow: 
                    user_config["flow"] = flow
                outbound_settings = {"vnext": [{"address": hosa, "port": port, "users": [user_config]}]}

            elif prot == 'trojan':
                outbound_settings = {"servers": [{"address": hosa, "port": port, "password": use}]}
            elif prot == 'ss':
                
                outbound_settings = {
                "servers": [{
                    "address": hosa,
                    "port": port,
                    "method": method,     
                    "password": password  
                }]
                }

            elif prot== 'vmess':
                
                outbound_settings = {
                "vnext": [{
                    "address": hosa,
                    "port": port,
                    "users": [{
                        "id": use,
                        "alterId": 0,
                        "security": "auto"
                    }]
                }]
                }
            data = {
            "inbounds": [{"port": local_port, "listen": "127.0.0.1", "protocol": "http"}],
            "outbounds": [{
                "protocol": prot,
                "settings": outbound_settings,
                "streamSettings": stream_settings
            }]
            }
        
        
            with open(config_file, "w", encoding="utf-8") as json_file:
                json.dump(data, json_file, indent=4)

        except Exception:
            print(f"Ошибка проверки узла (или таймаут)")
            return None
            
        
        process = await asyncio.create_subprocess_exec(
            XRAY_BIN, '-c', config_file,
            stdout=asyncio.subprocess.DEVNULL, 
            stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.sleep(2)

        
        try:
            
            async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{local_port}") as proxy_client:
                start_time = time.perf_counter()
                response = await proxy_client.get('http://www.gstatic.com/generate_204', timeout=15.0)
                end_time = time.perf_counter()
                ping = int((end_time-start_time)*1000)
                
                if response.status_code == 204:
                    print(f" {hosa} Пинг: {ping} мс")
                    
                    return {"link": link, "ping": ping}
                    
        except Exception as e:
            print(f" {hosa} не работает. Причина: {type(e).__name__}")
            return None
            
        finally:
            try:
                if process.returncode is None:
                    process.terminate()
                await process.wait()
            except ProcessLookupError:
                pass
            
            
            
            try:
                os.remove(config_file)
            except OSError:
                pass

async def main():
    


    async with httpx.AsyncClient() as client:
        response = await client.get('https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt', timeout=15.0)


        # print(response.text)
        lines=response.text.splitlines()

        valid_protocols = ('vless://', 'vmess://', 'trojan://', 'ss://')

        vless_links = clean_vless_links = [line.strip() for line in lines if line.strip().startswith(valid_protocols)]

        vl=set(vless_links)
        vle=list(vl)
        
        # print(vless_links)
        
        

        sem = asyncio.Semaphore(10) 
        tasks = []

        for index, link in enumerate(vle):
            tasks.append(check_xray(sem, link, index))
        
        print(f"Подготовлено {len(tasks)} задач. Начинаю проверять))")
    
    
        results = await asyncio.gather(*tasks)
    
    
        good_proxies = [r for r in results if r is not None]
    
        print(f"Найдено рабочих: {len(good_proxies)}")

        good_proxies.sort(key=lambda x: x["ping"])
        with open("good_proxies.txt", "w", encoding="utf-8") as f:
            for proxy in good_proxies:
                f.write(proxy["link"] + "\n")
                
        print(f"Все рабочие серверы успешно сохранены в файл 'good_proxies.txt'!")

asyncio.run(main())