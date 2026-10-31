"""Opt-in, serial AAA role-case reuse; audit and lifecycle cases stay fresh."""

from contextlib import contextmanager
import logging
import time

import pytest

from tests.common.fixtures.grpc_fixtures import _get_target_duthost, _gnmi_same_image_tls_flow
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

logger = logging.getLogger(__name__)
PRINCIPAL = "test.client.gnmi.sonic"
ROLE_KEY = "GNMI_CLIENT_CERT|{}".format(PRINCIPAL)
METADATA_KEY = "DEVICE_METADATA|localhost"


class _RoleTlsOwner:
    """One lazy TLS lifecycle per contiguous sequence of compatible cases.

    Suspend before *any* other case in this module. This avoids overlapping
    checkpoints/certificate files even with an explicit interleaved node list.
    A setup/cleanup error invalidates reuse rather than trusting dirty state.
    Test-body failures still run restoration and verification. If those pass,
    pytest may continue sharing; setup or cleanup failures poison the owner.
    """

    def __init__(self, verifier=None):
        self.verifier = verifier
        self.flow = None
        self.fixture = None
        self.broken = False
        self.log_request = None
        self.log_analyzer = None

    def close(self):
        flow, self.flow = self.flow, None
        self.fixture = None
        if flow is not None:
            try:
                next(flow)
            except StopIteration:
                return
            except BaseException:
                self.broken = True
                raise
            self.broken = True
            raise RuntimeError("TLS lifecycle yielded more than once")

    def close_with_logs(self):
        """Cover module teardown, after the last function analyzer has finished.

        Keep the last role request (including its disable marker) and analyzer
        for platform/test ignore patterns. Do not reuse its markers or expected
        messages: those belong to the already-analyzed function window.
        """
        if self.flow is None:
            return
        analyzer = marker = None
        try:
            request = self.log_request
            if (request is not None and not request.config.getoption("--disable_loganalyzer")
                    and "disable_loganalyzer" not in request.keywords):
                analyzer = LogAnalyzer(ansible_host=self.fixture.duthost,
                                       marker_prefix="gnmi_aaa_tls_teardown", request=request)
                analyzer.load_common_config()
                if self.log_analyzer is not None:
                    analyzer.ignore_regex.extend(self.log_analyzer.ignore_regex)
                marker = analyzer.init()
        finally:
            # Even construction/config/init failures must not strand TLS. A
            # nested finally also analyzes partial/failed cleanup and lets both
            # failures appear in the chained traceback if analysis fails too.
            try:
                self.close()
            finally:
                if marker is not None:
                    analyzer.analyze(marker)

    def acquire(self, duthosts, ptfhost, request):
        if self.broken:
            raise RuntimeError("AAA TLS cleanup failed; refusing further reuse")
        if self.flow is None:
            duthost = _get_target_duthost(duthosts, request)
            self.flow = _gnmi_same_image_tls_flow(duthost, ptfhost, verifier=self.verifier)
            try:
                self.fixture = next(self.flow)
                self.fixture._same_image_state.case_save()
            except BaseException:
                # A failed generator may already be exhausted after failed
                # cleanup; conservatively forbid another setup in this module.
                self.broken = True
                self.close()
                raise
        if self.fixture.duthost is not _get_target_duthost(duthosts, request):
            self.close()
            raise RuntimeError("Cannot reuse AAA TLS across different DUTs")
        return self.fixture

    @contextmanager
    def case(self, duthosts, ptfhost, request):
        fixture = self.acquire(duthosts, ptfhost, request)
        try:
            try:
                fixture.pygnmi_client.close()
                fixture._same_image_state.case_verify()
            except BaseException:
                self.broken = True
                raise
            try:
                yield fixture
            finally:
                # Nested finally guarantees restoration if client close fails.
                try:
                    fixture.pygnmi_client.close()
                except BaseException:
                    self.broken = True
                    raise
                finally:
                    try:
                        fixture._same_image_state.case_restore()
                        fixture._same_image_state.case_verify()
                    except BaseException:
                        # Do not let a later case hide failed restoration or an
                        # unrelated leak even if the outer rollback succeeds.
                        self.broken = True
                        raise
        except BaseException:
            # Report the mismatch before the full TLS rollback can hide it.
            self.close()
            raise


@pytest.fixture(scope="module")
def gnmi_aaa_tls_owner(core_dump_and_config_check, gnmi_original_service_verifier):
    # Explicit ordering: restore TLS before generic config checking/recovery.
    owner = _RoleTlsOwner(verifier=gnmi_original_service_verifier)
    try:
        yield owner
    finally:
        owner.close_with_logs()


def gnmi_aaa_case_boundary(request, gnmi_aaa_tls_owner):
    # This fixture is autouse only in the opting-in AAA module. Check fixture
    # membership, not node names, so renames cannot accidentally enable reuse.
    if gnmi_aaa_tls_owner.broken:
        raise RuntimeError("AAA TLS cleanup failed; refusing further cases")
    if "gnmi_aaa_role_tls" not in request.fixturenames:
        gnmi_aaa_tls_owner.close()


@pytest.fixture
def gnmi_aaa_role_tls(request, duthosts, ptfhost, gnmi_aaa_tls_owner, gnmi_aaa_case_boundary, loganalyzer):
    started = time.monotonic()
    try:
        with gnmi_aaa_tls_owner.case(duthosts, ptfhost, request) as fixture:
            gnmi_aaa_tls_owner.log_request = request
            gnmi_aaa_tls_owner.log_analyzer = (loganalyzer or {}).get(fixture.duthost.hostname)
            logger.info("AAA TLS case setup: %.3fs", time.monotonic() - started)
            yield fixture
    finally:
        logger.info("AAA TLS case lifecycle: %.3fs", time.monotonic() - started)
