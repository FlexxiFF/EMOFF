import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
import asyncio
from aiohttp import web
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

online_writer = None
whisper_writer = None
bot_state = {
    "key": None,
    "iv": None,
    "region": None,
    "uid": None,
    "command_queue": asyncio.Queue()
}

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB51"}

def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password, retry_count=3, retry_delay=5):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "ffmconnect.live.gop.garenanow.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    
    timeout = aiohttp.ClientTimeout(total=15)
    for attempt in range(retry_count + 1):
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.post(url, headers=Hr, data=data) as response:
                    if response.status == 429:  # Rate limited
                        print(f"  > Auth server returned status code: {response.status} (Rate Limited)")
                        if attempt < retry_count:
                            print(f"  > Retrying in {retry_delay} seconds... (Attempt {attempt + 1}/{retry_count})")
                            await asyncio.sleep(retry_delay)
                            continue
                        else:
                            print(f"  > FAILED: Rate limit exceeded after {retry_count + 1} attempts.")
                            return "Rate limit exceeded", None
                    elif response.status != 200: 
                        print(f"  > Auth server returned status code: {response.status}")
                        if attempt < retry_count:
                            print(f"  > Retrying in {retry_delay} seconds... (Attempt {attempt + 1}/{retry_count})")
                            await asyncio.sleep(retry_delay)
                            continue
                        else:
                            return "Failed to get access token", None
                    
                    resp_json = await response.json()
                    open_id = resp_json.get("open_id")
                    access_token = resp_json.get("access_token")
                    return (open_id, access_token) if open_id and access_token else (None, None)
            except asyncio.TimeoutError:
                print("  > ERROR: Connection to the authentication server timed out.")
                if attempt < retry_count:
                    print(f"  > Retrying in {retry_delay} seconds... (Attempt {attempt + 1}/{retry_count})")
                    await asyncio.sleep(retry_delay)
                    continue
                else:
                    return None, None
            except aiohttp.ClientConnectorError as e:
                print(f"  > ERROR: Could not connect to the authentication server. Details: {e}")
                if attempt < retry_count:
                    print(f"  > Retrying in {retry_delay} seconds... (Attempt {attempt + 1}/{retry_count})")
                    await asyncio.sleep(retry_delay)
                    continue
                else:
                    return None, None
    return None, None


async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.118.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return  await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    
async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     
async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'
    
async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT):
    if TypE == 'ChaT' and ChaT: whisper_writer.write(PacKeT) ; await whisper_writer.drain()
    elif TypE == 'OnLine' and OnLinE: online_writer.write(PacKeT) ; await online_writer.drain()
    else: print(f'UnsoPorTed TypE or Writer is None! Type: {TypE}')
           
async def TcPOnLine(ip, port, key, iv, AutHToKen, reconnect_delay=5.0):
    global online_writer
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break
                
                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    try:
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        packet = json.loads(packet)
                        OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                        JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key,iv)
                        await SEndPacKeT(None , whisper_writer , 'ChaT' , JoinCHaT)

                        message = f'Hi! I am a bot from CLOUD ENGINE'
                        P = await SEndMsG(0 , message , OwNer_UiD , OwNer_UiD , key , iv)
                        await SEndPacKeT(None , whisper_writer , 'ChaT' , P)
                    except Exception:
                        pass
            online_writer.close() ; await online_writer.wait_closed() ; online_writer = None
        except Exception as e: print(f"- ErroR With Online TCP {ip}:{port} - {e}") ; online_writer = None
        await asyncio.sleep(reconnect_delay)
                            
async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region, reconnect_delay=5.0):
    global whisper_writer
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print(f' - BoT ConnEcTed WiTh CLan ({clan_id}) ChaT SuccEssFuLy ! ')
                pK = await AuthClan(clan_id , clan_compiled_data , key , iv)
                if whisper_writer: whisper_writer.write(pK) ; await whisper_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data: break
                
                if data.hex().startswith("120000"):
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        inPuTMsG = response.Data.msg.lower()

                        if inPuTMsG in ("hi" , "hello" , "help"):
                            message = 'Use the web panel to control me!\n[C][FF2400]DISCORD : CLOUD ENGINE'
                            P = await SEndMsG(response.Data.chat_type , message , uid , chat_id , key , iv)
                            await SEndPacKeT(None , whisper_writer , 'ChaT' , P)
                    except Exception:
                        pass
            whisper_writer.close() ; await whisper_writer.wait_closed() ; whisper_writer = None
        except Exception as e: print(f"ErroR with Chat TCP {ip}:{port} - {e}") ; whisper_writer = None
        await asyncio.sleep(reconnect_delay)

async def command_processor():
    print("✓ Command processor started. Ready for web panel commands.")
    while True:
        command = await bot_state["command_queue"].get()
        action = command.get("action")
        print(f"--> Received command from web panel: {action}")

        key, iv, region, uid = bot_state["key"], bot_state["iv"], bot_state["region"], bot_state["uid"]

        if not online_writer:
            print("[ERROR] Cannot execute command, bot is not online.")
            bot_state["command_queue"].task_done()
            continue

        try:
            if action == "emote":
                emote_id = command.get("emote_id")
                player_ids = command.get("player_ids", [])
                for target_id in player_ids:
                    emote_packet = await Emote_k(target_id, emote_id, key, iv, region)
                    await SEndPacKeT(online_writer, None, 'OnLine', emote_packet)
                    print(f"Sent emote {emote_id} to {target_id}")
                    await asyncio.sleep(0.2)
            
            elif action == "emote_batch":
                assignments = command.get("assignments", []) 
                for assignment in assignments:
                    target_id = assignment.get("player_id")
                    emote_id = assignment.get("emote_id")
                    if target_id and emote_id:
                        emote_packet = await Emote_k(target_id, emote_id, key, iv, region)
                        await SEndPacKeT(online_writer, None, 'OnLine', emote_packet)
                        print(f"Sent assigned emote {emote_id} to {target_id}")
                        await asyncio.sleep(0.2)

            elif action == "join_squad":
                team_code = command.get("team_code")
                packet = await GenJoinSquadsPacket(team_code, key, iv)
                await SEndPacKeT(online_writer, None, 'OnLine', packet)
                print(f"Attempting to join squad with code: {team_code}")

            elif action == "quick_invite":
                player_id_to_invite = command.get("player_id") 
                if not player_id_to_invite:
                    print("[ERROR] Quick Invite requires a player_id from the web panel.")
                    continue
                
                print(f"Starting invite process for player: {player_id_to_invite}")
                
                packet_open = await OpEnSq(key, iv, region)
                await SEndPacKeT(online_writer, None, 'OnLine', packet_open)
                await asyncio.sleep(0.5)

                packet_ch = await cHSq(5, player_id_to_invite, key, iv, region)
                await SEndPacKeT(online_writer, None, 'OnLine', packet_ch)
                await asyncio.sleep(0.5)

                packet_inv = await SEnd_InV(5, player_id_to_invite, key, iv, region)
                await SEndPacKeT(online_writer, None, 'OnLine', packet_inv)
                print(f"Sent invite to {player_id_to_invite}")
                print("Invite process complete. Bot will remain in the squad.")

            elif action == "leave_squad":
                packet = await ExiT(uid, key, iv)
                await SEndPacKeT(online_writer, None, 'OnLine', packet)
                print("Leaving current squad...")

        except Exception as e:
            print(f"[ERROR] Failed to execute command '{action}': {e}")
        
        bot_state["command_queue"].task_done()

async def handle_command(request):
    try:
        data = await request.json()
        await bot_state["command_queue"].put(data)
        return web.json_response({"status": "ok", "message": f"Command '{data.get('action')}' queued successfully."}, status=200)
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)}, status=500)

async def run_web_server():
    app = web.Application()
    app.router.add_post('/command', handle_command)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 8081)
    await site.start()
    print("✓ Internal API server started at http://127.0.0.1:8081")
    await asyncio.Event().wait()

async def MaiiiinE():
    print("STARTING BOT FOR INDIA (IND) REGION")
    
    Uid , Pw = '4282473181','6EE6DAA9383F589D9792B73854101C200B78B199C5B2273EC038D6BA5D04837F'
    
    print("\n[STEP 1/4] Generating access token...")
    open_id , access_token = await GeNeRaTeAccEss(Uid , Pw, retry_count=5, retry_delay=10)
    if not open_id or not access_token: 
        print("  > FAILED: Could not get access token. Check credentials or network block. Restarting...")
        return None
    print("  > SUCCESS: Access token generated.")
    
    print("[STEP 2/4] Performing major login...")
    PyL = await EncRypTMajoRLoGin(open_id , access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE: 
        print("  > FAILED: Account might be banned or not registered. Restarting...")
        return None
    print("  > SUCCESS: Major login complete.")

    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    
    bot_state["key"] = MajoRLoGinauTh.key
    bot_state["iv"] = MajoRLoGinauTh.iv
    bot_state["region"] = MajoRLoGinauTh.region
    bot_state["uid"] = TarGeT
    timestamp = MajoRLoGinauTh.timestamp
    
    print("[STEP 3/4] Fetching login data and server ports...")
    LoGinDaTa = await GetLoginData(UrL , PyL , ToKen)
    if not LoGinDaTa: 
        print("  > FAILED: Could not get server ports from login data. Restarting...")
        return None
    print("  > SUCCESS: Login data received.")
    
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port

    print("[STEP 4/4] Parsing connection details...")
    try:
        OnLineiP, OnLineporT = OnLinePorTs.rsplit(":", 1)
        ChaTiP, ChaTporT = ChaTPorTs.rsplit(":", 1)
        if OnLineiP.startswith('[') and OnLineiP.endswith(']'): OnLineiP = OnLineiP[1:-1]
        if ChaTiP.startswith('[') and ChaTiP.endswith(']'): ChaTiP = ChaTiP[1:-1]
        print(f"  > Online Server: {OnLineiP}:{OnLineporT}")
        print(f"  > Chat Server:   {ChaTiP}:{ChaTporT}")
    except ValueError:
        print("\n" + "="*50)
        print("  > CRITICAL ERROR: Failed to parse IP and Port from the server.")
        print(f"  > Received Online String: '{OnLinePorTs}'")
        print(f"  > Received Chat String:   '{ChaTPorTs}'")
        print("  > The bot cannot continue and will restart.")
        print("="*50 + "\n")
        return None 
    print("  > SUCCESS: Connection details parsed.")
    
    acc_name = LoGinDaTaUncRypTinG.AccountName
    
    equie_emote(ToKen,UrL)
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , bot_state["key"] , bot_state["iv"])
    ready_event = asyncio.Event()
    
    print("\n[+] Initializing TCP connections...")
    task_chat = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , bot_state["key"] , bot_state["iv"] , LoGinDaTaUncRypTinG , ready_event , bot_state["region"]))
    
    await ready_event.wait() 
    await asyncio.sleep(1)
    
    task_online = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , bot_state["key"] , bot_state["iv"] , AutHToKen))
    task_web_server = asyncio.create_task(run_web_server())
    task_command_processor = asyncio.create_task(command_processor())

    os.system('cls' if os.name == 'nt' else 'clear')
    print(render('CLOUD ENGINE', colors=['white', 'red'], align='center'))
    print(f" - BoT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}\n")
    print(f" - BoT sTaTus > GooD | CLOUD ENGINE ! (:")    
    print(f" - SCRIPT BY > CLOUD ENGINE ! (:")    
    
    await asyncio.gather(task_chat, task_online, task_web_server, task_command_processor)
    
async def StarTinG():
    while True:
        try: 
            await asyncio.wait_for(MaiiiinE() , timeout = 7 * 60 * 60)
        except asyncio.TimeoutError: 
            print("Token ExpiRed ! , ResTartinG")
        except Exception as e: 
            print(f"ErroR TcP - {e} => ResTarTinG ...")
            await asyncio.sleep(5) 

if __name__ == '__main__':
    try:
        asyncio.run(StarTinG())
    except KeyboardInterrupt:
        print("\nBot shutting down.")