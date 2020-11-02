import asyncio
import httpx
import uuid
from typing import Optional, Union, List

import ms_cv
from auth.models import SisuAuthorizationResponse, XSTSResponse
from auth.signed_session import SignedSession
from auth.request_signer import RequestSigner

from smartglass_models import SmartglassConsoleList, \
    SmartglassConsoleStatus, CommandResponse, VolumeDirection, InputKeyType,\
    MediaCommand, InstalledPackagesList, StorageDevicesList,\
    OperationStatusResponse


class SmartglassApi:
    def __init__(
        self,
        request_signer: RequestSigner,
        xsts_token: XSTSResponse,
        user_agent: str = 'Xbox/2008.0915.0311 CFNetwork/1197 Darwin/20.0.0'
    ):
        self.cv = ms_cv.CorrelationVector()

        self.user_agent = user_agent
        self.session = SignedSession(request_signer)
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Authorization': xsts_token.authorization_header_value,
            'x-xbl-contract-version': '4',
            'skillplatform': 'RemoteManagement'
        })

        self.smartglass_session_id = str(uuid.uuid4())

    async def fetch_operation_status(
        self,
        operation_id: str,
        device_id: str
    ) -> OperationStatusResponse:
        url = f'https://xccs.xboxlive.com/opStatus'
        headers = {
            'MS-CV': self.cv.increment(),
            'x-xbl-contract-version': '3',
            'x-xbl-opId': operation_id,
            'x-xbl-deviceId': device_id
        }
        request = self.session.build_request('GET', url, headers=headers)
        resp = await self.session.send_signed(request)
        resp.raise_for_status()
        return OperationStatusResponse.parse_obj(resp.json())

    async def _fetchList(self, list_name: str, query_params: dict = None) -> httpx.Response:
        url = f'https://xccs.xboxlive.com/lists/{list_name}'
        headers = {
            'MS-CV': self.cv.increment()
        }
        request = self.session.build_request('GET', url, headers=headers, params=query_params)
        resp = await self.session.send_signed(request)
        resp.raise_for_status()
        return resp

    async def get_console_list(self) -> SmartglassConsoleList:
        query_params = {
            'queryCurrentDevice': 'false',
            'includeStorageDevices': 'true'
        }
        resp = await self._fetchList("devices", query_params)
        return SmartglassConsoleList.parse_obj(resp.json())

    async def get_storage_devices(self, device_id: str) -> StorageDevicesList:
        query_params = {
            'deviceId': device_id
        }
        resp = await self._fetchList("storageDevices", query_params)
        return StorageDevicesList.parse_obj(resp.json())

    async def get_installed_apps(self, device_id: str) -> InstalledPackagesList:
        query_params = {
            'deviceId': device_id
        }
        resp = await self._fetchList("installedApps", query_params)
        return InstalledPackagesList.parse_obj(resp.json())

    async def get_console_status(self, console_live_id: str) -> SmartglassConsoleStatus:
        url = f'https://xccs.xboxlive.com/consoles/{console_live_id}'
        headers = {
            'MS-CV': self.cv.increment()
        }
        request = self.session.build_request('GET', url, headers=headers)
        resp = await self.session.send_signed(request)
        resp.raise_for_status()
        return SmartglassConsoleStatus.parse_obj(resp.json())

    async def _send_command(
        self,
        console_liveid: str,
        command_type: str,
        command: str,
        parameters: Optional[list] = None
    ) -> CommandResponse:
        if not parameters:
            parameters = [{}]

        url = f'https://xccs.xboxlive.com/commands'
        headers = {
            'MS-CV': self.cv.increment()
        }
        json_body = {
            "destination": "Xbox",
            "type": command_type,
            "command": command,
            "sessionId": self.smartglass_session_id,
            "sourceId": "com.microsoft.smartglass",
            "parameters": parameters,
            "linkedXboxId": console_liveid
        }
        request = self.session.build_request('POST', url, headers=headers, json=json_body)
        resp = await self.session.send_signed(request)
        resp.raise_for_status()
        return CommandResponse.parse_obj(resp.json())

    async def command_power_on(self, console_live_id: str) -> CommandResponse:
        return await self._send_command(console_live_id, "Power", "WakeUp")

    async def command_power_off(self, console_live_id: str) -> CommandResponse:
        return await self._send_command(console_live_id, "Power", "TurnOff")

    async def command_power_reboot(self, console_live_id: str) -> CommandResponse:
        return await self._send_command(console_live_id, "Power", "Reboot")

    async def command_audio_mute(self, console_live_id: str) -> CommandResponse:
        return await self._send_command(console_live_id, "Audio", "Mute")

    async def command_audio_unmute(self, console_live_id: str) -> CommandResponse:
        return await self._send_command(console_live_id, "Audio", "Unmute")

    async def command_audio_volume(
        self, console_live_id: str, direction: VolumeDirection, amount: int = 1
    ) -> CommandResponse:
        params = [{"direction": direction.value, "amount": str(amount)}]
        return await self._send_command(console_live_id, "Audio", "Volume", params)

    async def command_config_digital_assistant_remote_control(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Config", "DigitalAssistantRemoteControl")

    async def command_config_remote_access(
        self,
        console_live_id: str,
        enable: bool
    ) -> CommandResponse:
        params = [{"enabled": str(enable)}]
        return await self._send_command(console_live_id, "Config", "RemoteAccess", params)

    async def command_config_allow_console_streaming(
        self,
        console_live_id: str,
        enable: bool
    ) -> CommandResponse:
        params = [{"enabled": str(enable)}]
        return await self._send_command(console_live_id, "Config", "AllowConsoleStreaming", params)

    async def command_game_capture_gameclip(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Game", "CaptureGameClip")

    async def command_game_capture_screenshot(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Game", "CaptureScreenshot")

    async def command_game_invite_party_to_game(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Game", "InvitePartyToGame")

    async def command_game_invite_to_party(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Game", "InviteToParty")

    async def command_game_kick_from_party(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Game", "KickFromParty")

    async def command_game_leave_party(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Game", "LeaveParty")

    async def command_game_set_online_status(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Game", "SetOnlineStatus")

    async def command_game_start_a_party(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Game", "StartAParty")

    async def command_game_start_broadcasting(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Game", "StartBroadcasting")

    async def command_game_stop_broadcasting(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Game", "StopBroadcasting")

    async def command_gamestreaming_start_management_service(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "GameStreaming", "StartStreamingManagementService")

    async def command_gamestreaming_stop_streaming(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "GameStreaming", "StopStreaming")

    async def command_marketplace_redeem_code(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Marketplace", "RedeemCode")

    async def command_marketplace_search(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Marketplace", "Search")

    async def command_marketplace_search_store(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Marketplace", "SearchTheStore")

    async def command_marketplace_show_title(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Marketplace", "ShowTitle")

    async def command_media(
        self,
        console_live_id: str,
        media_command: MediaCommand
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Media", media_command.value)

    async def command_shell_activate_app_with_uri(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "ActivateApplicationWithUri")

    async def command_shell_activate_app_with_aumid(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "ActivateApplicationWithAumid")

    async def command_shell_activate_app_with_onestore_product_id(
        self,
        console_live_id: str,
        onestore_product_id: str
    ) -> CommandResponse:
        params = [{"oneStoreProductId": onestore_product_id}]
        return await self._send_command(console_live_id, "Shell", "ActivationApplicationWithOneStoreProductId", params)

    async def command_shell_allow_remote_management(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "AllowRemoteManagement")

    async def command_shell_change_view(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "ChangeView")

    async def command_shell_check_for_package_updates(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "CheckForPackageUpdates")

    async def command_shell_copy_packages(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "CopyPackages")

    async def command_shell_move_packages(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "MovePackages")

    async def command_shell_install_packages(
        self,
        console_live_id: str,
        big_cat_ids: List[str]
    ) -> CommandResponse:
        params = [{"bigCatIdList": ','.join(big_cat_ids)}]
        return await self._send_command(console_live_id, "Shell", "InstallPackages", params)

    async def command_shell_uninstall_package(
        self,
        console_live_id: str,
        instance_id: str
    ) -> CommandResponse:
        params = [{"instanceId": instance_id}]
        return await self._send_command(console_live_id, "Shell", "UninstallPackage", params)

    async def command_shell_update_packages(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "UpdatePackages")

    async def command_shell_eject_disk(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "EjectDisk")

    async def command_shell_go_back(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "GoBack")

    async def command_shell_go_home(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "GoHome")

    async def command_shell_pair_controller(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "PairController")

    async def command_shell_send_text_message(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "SendTextMessage")

    async def command_shell_show_guide_tab(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "ShowGuideTab")

    async def command_shell_sign_in(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "SignIn")

    async def command_shell_sign_out(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "SignOut")

    async def command_shell_launch_game(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "LaunchGame")

    async def command_shell_terminate_application(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "Shell", "TerminateApplication")

    async def command_shell_keyinput(
        self, console_live_id: str, key_type: InputKeyType
    ) -> CommandResponse:
        params = [{"keyType": key_type.value}]
        return await self._send_command(console_live_id, "Shell", "InjectKey", params)

    async def command_shell_textinput(
        self, console_live_id: str, text_input: str
    ) -> CommandResponse:
        params = [{"replacementString": text_input}]
        return await self._send_command(console_live_id, "Shell", "InjectString", params)

    async def command_tv_show_guide(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "TV", "ShowGuide")

    async def command_tv_watch_channel(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "TV", "WatchChannel")
