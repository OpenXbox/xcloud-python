import asyncio
import aiohttp
import uuid
from typing import Optional, List
from urllib.parse import urljoin

import ms_cv
from auth.models import SisuAuthorizationResponse, XSTSResponse
from auth.signed_session import SignedSession
from auth.request_signer import RequestSigner

from smartglass_models import SmartglassConsoleList, \
    SmartglassConsoleStatus, CommandResponse, VolumeDirection, InputKeyType,\
    MediaCommand, InstalledPackagesList, StorageDevicesList,\
    OperationStatusResponse


class SmartglassApi:
    BASE_URL = 'https://xccs.xboxlive.com'
    def __init__(
        self,
        request_signer: RequestSigner,
        xsts_token: XSTSResponse,
        user_agent: str = 'Xbox/2008.0915.0311 CFNetwork/1197 Darwin/20.0.0'
    ):
        self.cv = ms_cv.CorrelationVector()
        self.session = SignedSession(request_signer)

        self.user_agent = user_agent
        self.xsts_token = xsts_token
        self.smartglass_session_id = str(uuid.uuid4())

    @property
    def headers(self):
        return {
            'User-Agent': self.user_agent,
            'Authorization': self.xsts_token.authorization_header_value,
            'x-xbl-contract-version': '4',
            'skillplatform': 'RemoteManagement',
            'MS-CV': self.cv.increment()
        }

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
        params = [{"enabled": str(enable).capitalize()}]
        return await self._send_command(console_live_id, "Config", "RemoteAccess", params)

    async def command_config_allow_console_streaming(
        self,
        console_live_id: str,
        enable: bool
    ) -> CommandResponse:
        params = [{"enabled": str(enable).capitalize()}]
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

    async def command_tv_watch_channel(
        self,
        console_live_id: str
    ) -> CommandResponse:
        return await self._send_command(console_live_id, "TV", "WatchChannel")
