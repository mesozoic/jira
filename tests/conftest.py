from __future__ import annotations

import getpass
import hashlib
import logging
import os
import random
import re
import string
import sys
import time
import unittest
import weakref
from contextlib import ExitStack
from datetime import datetime, timezone
from functools import partialmethod
from time import sleep
from typing import Any, Iterator

import pytest
import requests_mock
import requests_mock.adapter
from typing_extensions import Self

from jira import JIRA
from jira.exceptions import JIRAError
from jira.resources import Issue

TEST_ROOT = os.path.dirname(__file__)
TEST_ICON_PATH = os.path.join(TEST_ROOT, "icon.png")
TEST_ATTACH_PATH = os.path.join(TEST_ROOT, "tests.py")

LOGGER = logging.getLogger(__name__)


allow_on_cloud = pytest.mark.allow_on_cloud
broken_test = pytest.mark.xfail


class JiraTestCase(unittest.TestCase):
    """Test case for all Jira tests.

    This is the base class for all Jira tests that require access to the
    Jira instance.

    It calls JiraTestManager() in the setUp() method.
    setUp() is the method that is called **before** each test is run.

    Where possible follow the:

    * GIVEN - where you set up any pre-requisites e.g. the expected result
    * WHEN  - where you perform the action and obtain the result
    * THEN  - where you assert the expectation vs the result

    format for tests.
    """

    jira: JIRA  # admin authenticated
    jira_normal: JIRA  # non-admin authenticated

    def setUp(self) -> None:
        """
        This is called before each test. If you want to add more for your tests,
        Run `super().setUp() in your custom setUp() to obtain these.
        """

        initialized = False
        try:
            self.test_manager = JiraTestManager()
            initialized = self.test_manager.initialized
        except Exception as e:
            # pytest with flaky swallows any exceptions re-raised in a try, except
            # so we log any exceptions for aiding debugging
            LOGGER.exception(e)
        self.assertTrue(initialized, "Test Manager setUp failed")

        self.jira = self.test_manager.jira_admin
        self.jira_normal = self.test_manager.jira_normal
        self.user_admin = self.test_manager.user_admin
        self.user_normal = self.test_manager.user_normal  # use this user where possible
        self.project_b = self.test_manager.project_b
        self.project_a = self.test_manager.project_a
        weakref.finalize(
            self,
            self._cleanup,
            test_manager=self.test_manager,
            projects=[self.project_a, self.project_b],
        )

    @property
    def identifying_user_property(self) -> str:
        """Literal["accountId", "name"]: Depending on if Jira Cloud or Server"""
        return "accountId" if self.is_jira_cloud_ci else "name"

    @property
    def is_jira_cloud_ci(self) -> bool:
        """is running on Jira Cloud"""
        return self.test_manager._cloud_ci

    def _cleanup(self, test_manager: JiraTestManager, projects: list[str]) -> None:
        """This is called when the object is set to be garbage collected."""
        for proj in projects:
            try:
                test_manager._remove_project(proj)
            except Exception:
                LOGGER.exception(f"Failed to remove project {proj}")


def rndstr():
    return "".join(random.sample(string.ascii_lowercase, 6))


def rndpassword():
    # generates a password of length 14
    s = (
        "".join(random.sample(string.ascii_uppercase, 5))
        + "".join(random.sample(string.ascii_lowercase, 5))
        + "".join(random.sample(string.digits, 2))
        + "".join(random.sample("~`!@#$%^&*()_+-=[]\\{}|;':<>?,./", 2))
    )
    return "".join(random.sample(s, len(s)))


def hashify(some_string, max_len=8):
    return hashlib.sha256(some_string.encode("utf-8")).hexdigest()[:max_len].upper()


def get_unique_project_name():
    user = re.sub("[^A-Z_]", "", getpass.getuser().upper())
    if "GITHUB_ACTION" in os.environ and "GITHUB_RUN_NUMBER" in os.environ:
        run_number = os.environ["GITHUB_RUN_NUMBER"]
        # please note that user underline (_) is not supported by
        # Jira even if it is documented as supported.
        return f"CI{hashify(f'{user}{run_number}',max_len=7)}"
    sep = chr(ord("A"))
    identifier = f"{user}{sep}{sys.version_info[0]}{sep}{sys.version_info[1]}"
    return f"Z{hashify(identifier)}"


class JiraTestManager:
    """Instantiate and populate the JIRA instance with data for tests.

    Attributes:
        CI_JIRA_ADMIN (str): Admin user account name.
        CI_JIRA_USER (str): Limited user account name.
        max_retries (int): number of retries to perform for recoverable HTTP errors.
        initialized (bool): if init was successful.
    """

    __shared_state: dict[Any, Any] = {}

    def __init__(self, jira_hosted_type=os.environ.get("CI_JIRA_TYPE", "Server")):
        """Instantiate and populate the JIRA instance"""
        self.__dict__ = self.__shared_state

        if not self.__dict__:
            self.initialized = False
            self.max_retries = 5
            self._cloud_ci = False

            if jira_hosted_type and jira_hosted_type.upper() == "CLOUD":
                self.set_jira_cloud_details()
                self._cloud_ci = True
            else:
                self.set_jira_server_details()

            jira_class_kwargs = {
                "server": self.CI_JIRA_URL,
                "logging": False,
                "validate": True,
                "max_retries": self.max_retries,
            }

            self.set_basic_auth_logins(**jira_class_kwargs)

            if not self.jira_admin.current_user():
                self.initialized = True
                sys.exit(3)

            # now we need to create some data to start with for the tests
            self.create_some_data()

        if not hasattr(self, "jira_normal") or not hasattr(self, "jira_admin"):
            pytest.exit("FATAL: WTF!?")

        if self._cloud_ci:
            self.user_admin = self.jira_admin.search_users(query=self.CI_JIRA_ADMIN)[0]
            self.user_normal = self.jira_admin.search_users(query=self.CI_JIRA_USER)[0]
        else:
            self.user_admin = self.jira_admin.search_users(self.CI_JIRA_ADMIN)[0]
            self.user_normal = self.jira_admin.search_users(self.CI_JIRA_USER)[0]
        self.initialized = True

    def set_jira_cloud_details(self):
        self.CI_JIRA_URL = "https://pycontribs.atlassian.net"
        self.CI_JIRA_ADMIN = os.environ["CI_JIRA_CLOUD_ADMIN"]
        self.CI_JIRA_ADMIN_PASSWORD = os.environ["CI_JIRA_CLOUD_ADMIN_TOKEN"]
        self.CI_JIRA_USER = os.environ["CI_JIRA_CLOUD_USER"]
        self.CI_JIRA_USER_PASSWORD = os.environ["CI_JIRA_CLOUD_USER_TOKEN"]
        self.CI_JIRA_ISSUE = os.environ.get("CI_JIRA_ISSUE", "Bug")

    def set_jira_server_details(self):
        self.CI_JIRA_URL = os.environ["CI_JIRA_URL"]
        self.CI_JIRA_ADMIN = os.environ["CI_JIRA_ADMIN"]
        self.CI_JIRA_ADMIN_PASSWORD = os.environ["CI_JIRA_ADMIN_PASSWORD"]
        self.CI_JIRA_USER = os.environ["CI_JIRA_USER"]
        self.CI_JIRA_USER_PASSWORD = os.environ["CI_JIRA_USER_PASSWORD"]
        self.CI_JIRA_ISSUE = os.environ.get("CI_JIRA_ISSUE", "Bug")

    def set_basic_auth_logins(self, **jira_class_kwargs):
        if self.CI_JIRA_ADMIN:
            self.jira_admin = JIRA(
                basic_auth=(self.CI_JIRA_ADMIN, self.CI_JIRA_ADMIN_PASSWORD),
                **jira_class_kwargs,
            )
            self.jira_sysadmin = JIRA(
                basic_auth=(self.CI_JIRA_ADMIN, self.CI_JIRA_ADMIN_PASSWORD),
                **jira_class_kwargs,
            )
            self.jira_normal = JIRA(
                basic_auth=(self.CI_JIRA_USER, self.CI_JIRA_USER_PASSWORD),
                **jira_class_kwargs,
            )
        else:
            raise RuntimeError("CI_JIRA_ADMIN environment variable is not set/empty.")

    def _project_exists(self, project_key: str) -> bool:
        """True if we think the project exists, else False.

        Assumes project exists if unknown Jira exception is raised.
        """
        try:
            self.jira_admin.project(project_key)
        except JIRAError as e:  # If the project does not exist a warning is thrown
            if "No project could be found" in str(e):
                return False
            LOGGER.exception("Assuming project '%s' exists.", project_key)
        return True

    def _remove_project(self, project_key):
        """Ensure if the project exists we delete it first"""

        wait_between_checks_secs = 2
        time_to_wait_for_delete_secs = 40
        wait_attempts = int(time_to_wait_for_delete_secs / wait_between_checks_secs)

        # TODO(ssbarnea): find a way to prevent SecurityTokenMissing for On Demand
        # https://jira.atlassian.com/browse/JRA-39153
        if self._project_exists(project_key):
            try:
                self.jira_admin.delete_project(project_key, enable_undo=False)
            except Exception:
                LOGGER.exception("Failed to delete '%s'.", project_key)

        # wait for the project to be deleted
        for _ in range(1, wait_attempts):
            if not self._project_exists(project_key):
                # If the project does not exist a warning is thrown
                # so once this is raised we know it is deleted successfully
                break
            sleep(wait_between_checks_secs)

        if self._project_exists(project_key):
            raise TimeoutError(
                " Project '{project_key}' not deleted after {time_to_wait_for_delete_secs} seconds"
            )

    def _create_project(
        self, project_key: str, project_name: str, force_recreate: bool = False
    ) -> int:
        """Create a project and return the id"""

        if not force_recreate and self._project_exists(project_key):
            pass
        else:
            self._remove_project(project_key)
            create_attempts = 6
            for _ in range(create_attempts):
                try:
                    if self.jira_admin.create_project(project_key, project_name):
                        break
                except JIRAError as e:
                    if "A project with that name already exists" not in str(e):
                        raise e
                time.sleep(1)
        return self.jira_admin.project(project_key).id

    def create_some_data(self):
        """Create some data for the tests"""

        # jira project key is max 10 chars, no letter.
        # [0] always "Z"
        # [1-6] username running the tests (hope we will not collide)
        # [7-8] python version A=0, B=1,..
        # [9] A,B -- we may need more than one project

        """ `jid` is important for avoiding concurrency problems when
        executing tests in parallel as we have only one test instance.

        jid length must be less than 9 characters because we may append
        another one and the Jira Project key length limit is 10.
        """

        self.jid = get_unique_project_name()

        self.project_a = self.jid + "A"  # old XSS
        self.project_a_name = f"Test user={getpass.getuser()} key={self.project_a} A"
        self.project_b = self.jid + "B"  # old BULK
        self.project_b_name = f"Test user={getpass.getuser()} key={self.project_b} B"
        self.project_sd = self.jid + "C"
        self.project_sd_name = f"Test user={getpass.getuser()} key={self.project_sd} C"

        self.project_a_id = self._create_project(self.project_a, self.project_a_name)
        self.project_b_id = self._create_project(
            self.project_b, self.project_b_name, force_recreate=True
        )

        sleep(1)  # keep it here as often Jira will report the
        # project as missing even after is created

        project_b_issue_kwargs = {
            "project": self.project_b,
            "issuetype": {"name": self.CI_JIRA_ISSUE},
        }
        self.project_b_issue1_obj = self.jira_admin.create_issue(
            summary=f"issue 1 from {self.project_b}", **project_b_issue_kwargs
        )
        self.project_b_issue1 = self.project_b_issue1_obj.key

        self.project_b_issue2_obj = self.jira_admin.create_issue(
            summary=f"issue 2 from {self.project_b}", **project_b_issue_kwargs
        )
        self.project_b_issue2 = self.project_b_issue2_obj.key

        self.project_b_issue3_obj = self.jira_admin.create_issue(
            summary=f"issue 3 from {self.project_b}", **project_b_issue_kwargs
        )
        self.project_b_issue3 = self.project_b_issue3_obj.key


def find_by_key(seq, key):
    for seq_item in seq:
        if seq_item["key"] == key:
            return seq_item


def find_by_key_value(seq, key):
    for seq_item in seq:
        if seq_item.key == key:
            return seq_item


def find_by_id(seq, id):
    for seq_item in seq:
        if seq_item.id == id:
            return seq_item


def find_by_name(seq, name):
    for seq_item in seq:
        if seq_item["name"] == name:
            return seq_item


@pytest.fixture()
def no_fields(monkeypatch):
    """When we want to test the __init__ method of the jira.client.JIRA
    we don't need any external calls to get the fields.

    We don't need the features of a MagicMock, hence we don't use it here.
    """
    monkeypatch.setattr(JIRA, "fields", lambda *args, **kwargs: [])


class MockJira:
    client: JIRA
    mocker: requests_mock.Mocker

    def __init__(self, version: str = "9.16.0"):
        self._context_stack = ExitStack()
        self._server = os.environ.get("CI_JIRA_URL", "http://localhost/jira")
        self._server_version = version
        self._auth = (
            os.environ.get("CI_JIRA_USER", "user"),
            os.environ.get("CI_JIRA_USER_PASSWORD", "password"),
        )
        self._issues: dict[str, dict[str, Any]] = {}  # by key
        self.mocker = requests_mock.Mocker()

    def __enter__(self) -> Self:
        self.mocker.__enter__()
        self._configure()
        return self

    def __exit__(self, type: Any, value: Any, traceback: Any) -> None:
        self.mocker.__exit__(type, value, traceback)

    def _configure(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        # can't use self.client._get_url because it's not created yet
        server_info_url = JIRA.JIRA_BASE_URL.format(
            server=self._server,
            rest_path=JIRA.DEFAULT_OPTIONS["rest_path"],
            rest_api_version=JIRA.DEFAULT_OPTIONS["rest_api_version"],
            path="serverInfo",
        )
        self.get(
            server_info_url,
            json={
                "baseUrl": self._server,
                "version": self._server_version,
                "versionNumbers": [int(n) for n in self._server_version.split(".")],
                "buildNumber": 1,
                "buildDate": now,
                "serverTime": now,
                "serverTitle": "MockJira",
            },
        )
        self.client = JIRA(self._server, basic_auth=self._auth)

    def issue(self, key: str = "", **fields: Any) -> Issue:
        """
        Registers GET responses for an issue key.
        """
        key = key or "CI-1"
        self_id = str(id(key))
        issue_json = self._issues[key] = {
            "expand": "renderedFields,names,schema,operations,editmeta,changelog,versionedRepresentations",
            "id": self_id,
            "self": self.client._get_url(f"issue/{self_id}"),
            "key": key,
            "fields": fields,
        }
        self.get(f"issue/{key}", json=issue_json)
        self.get(f"issue/{self_id}", json=issue_json)
        return self.client.issue(key)

    def register_request(
        self,
        method: str,
        url: str | re.Pattern,
        *args: Any,
        **kwargs: Any,
    ) -> requests_mock.adapter._Matcher:
        """
        Wrapper around request_mock's Matcher interface which adds some Jira-specific behavior.
        """

        # shortcut to allow e.g. mock_jira.post("whatever") without specifying the full URL
        if isinstance(url, str) and not url.startswith("http"):
            url = self.client._get_url(
                url,
                base=(
                    self.client.AGILE_BASE_URL
                    if kwargs.pop("agile", None)
                    else self.client.JIRA_BASE_URL
                ),
            )

        # Any time a test mocks the URL for an issue, we need to ensure
        # that our mock request matchers catch both issue key *and* issue ID.
        if isinstance(url, str) and (
            match := re.search(r"issue/([A-Z][A-Z0-9]+-[1-9][0-9]*)\b", url)
        ):
            # Only do this if we recognize the issue key as one we've mocked.
            if issue_id := self._issues.get((issue_key := match[1]), {}).get("id"):
                alt_url = url.replace(f"/issue/{issue_key}", f"/issue/{issue_id}")
                url = re.compile(f"^({re.escape(url)}|{re.escape(alt_url)})$")

        return self.mocker.request(method, url, *args, **kwargs)

    get = partialmethod(register_request, "GET")
    post = partialmethod(register_request, "POST")
    patch = partialmethod(register_request, "PATCH")
    put = partialmethod(register_request, "PUT")
    delete = partialmethod(register_request, "DELETE")


@pytest.fixture
def mock_jira(requests_mock) -> Iterator[MockJira]:
    """
    Fixture that intercepts network traffic to Jira and allows tests to define
    how the mocked network responses will behave.
    """
    with MockJira() as m:
        yield m
