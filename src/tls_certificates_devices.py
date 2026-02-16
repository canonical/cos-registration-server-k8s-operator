#!/usr/bin/env python3

"""Custom TLS certificates requirer for pre-generated CSRs.

This module provides a simplified TLS certificates requirer that works with
pre-generated Certificate Signing Requests (CSRs). Unlike the standard
TLSCertificatesRequiresV4, this implementation accepts CSR strings directly
without generating new private keys or CSRs.

This is designed to be easily replaceable if the upstream library adds
support for pre-generated CSRs in the future.
"""

import copy
import logging
from typing import List, Optional

from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
    CertificateSigningRequest,
    DataValidationError,
    ProviderCertificate,
    RequirerCertificateRequest,
    # Those should not be imported outside of this module, but are needed
    # to ensure type safety with pydantic. Hence are imported to avoid code duplication.
    _CertificateSigningRequest,
    _ProviderApplicationData,
    _RequirerData,
)
from ops import BoundEvent, CharmBase, EventBase, EventSource, Object
from ops.charm import CharmEvents
from ops.model import ModelError

logger = logging.getLogger(__name__)


class CertificatesRequirerCharmEvents(CharmEvents):
    """List of events that the TLS Certificates requirer charm can leverage."""

    certificate_available = EventSource(CertificateAvailableEvent)


class TLSCertificatesRequiresV4(Object):
    """A class to manage the TLS certificates interface for pre-generated CSRs."""

    on = CertificatesRequirerCharmEvents()  # type: ignore[reportAssignmentType]

    def __init__(
        self,
        charm: CharmBase,
        relationship_name: str,
        certificate_signing_requests: List[CertificateSigningRequest],
        refresh_events: List[BoundEvent] = [],
    ):
        """Create a new instance of the TLSCertificatesRequiresV4 class.

        Args:
            charm (CharmBase): The charm instance to relate to.
            relationship_name (str): The name of the relation that provides the certificates.
            certificate_signing_requests (List[CertificateSigningRequest]): A list of pre-generated CSR objects.
            refresh_events (List[BoundEvent]): A list of events to trigger a refresh of
              the certificates.
        """
        super().__init__(charm, relationship_name)

        self.charm = charm
        self.relationship_name = relationship_name

        self.certificate_signing_requests = certificate_signing_requests

        self.framework.observe(charm.on[relationship_name].relation_created, self._configure)
        self.framework.observe(charm.on[relationship_name].relation_changed, self._configure)
        for event in refresh_events:
            self.framework.observe(event, self._configure)

    def _configure(self, _: Optional[EventBase] = None):
        """Handle TLS Certificates Relation Data.

        This method is called during TLS relation events.
        It will send certificate requests if they haven't been sent yet.
        It will find available certificates and emit events.
        """
        if not self._tls_relation_created():
            logger.debug("TLS relation not created yet.")
            return
        self._cleanup_certificate_requests()
        self._send_certificate_requests()
        self._find_available_certificates()

    def sync(self) -> None:
        """Sync TLS Certificates Relation Data.

        This method allows the requirer to sync the TLS certificates relation data
        without waiting for the refresh events to be triggered.
        """
        self._configure()

    def get_csrs_from_requirer_relation_data(self) -> List[RequirerCertificateRequest]:
        """Return list of requirer's CSRs from relation data."""
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return []
        try:
            requirer_relation_data = _RequirerData.load(relation.data[self.model.unit])
        except DataValidationError:
            logger.warning("Invalid relation data")
            return []
        requirer_csrs = []
        for csr in requirer_relation_data.certificate_signing_requests:
            requirer_csrs.append(
                RequirerCertificateRequest(
                    relation_id=relation.id,
                    certificate_signing_request=CertificateSigningRequest.from_string(
                        csr.certificate_signing_request
                    ),
                    is_ca=csr.ca if csr.ca else False,
                )
            )
        return requirer_csrs

    def get_provider_certificates(self) -> List[ProviderCertificate]:
        """Return list of certificates from the provider's relation data."""
        return self._load_provider_certificates()

    def _load_provider_certificates(self) -> List[ProviderCertificate]:
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return []
        if not relation.app:
            logger.debug("No remote app in relation: %s", self.relationship_name)
            return []
        try:
            provider_relation_data = _ProviderApplicationData.load(relation.data[relation.app])
        except DataValidationError:
            logger.warning("Invalid relation data")
            return []
        return [
            certificate.to_provider_certificate(relation_id=relation.id)
            for certificate in provider_relation_data.certificates
        ]

    def _request_certificate(self, csr: CertificateSigningRequest, is_ca: bool = False) -> None:
        """Add CSR to relation data."""
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return
        new_csr = _CertificateSigningRequest(
            certificate_signing_request=str(csr).strip(), ca=is_ca
        )
        try:
            requirer_relation_data = _RequirerData.load(relation.data[self.model.unit])
        except DataValidationError:
            requirer_relation_data = _RequirerData(
                certificate_signing_requests=[],
            )
        new_relation_data = list(requirer_relation_data.certificate_signing_requests)
        new_relation_data.append(new_csr)
        try:
            _RequirerData(certificate_signing_requests=new_relation_data).dump(
                relation.data[self.model.unit]
            )
            logger.info("Certificate signing request added to relation data.")
        except ModelError:
            logger.warning("Failed to update relation data")

    def _send_certificate_requests(self):
        """Send all CSRs that haven't been sent yet."""
        existing_csrs = self.get_csrs_from_requirer_relation_data()
        existing_csr_strings = {
            str(csr.certificate_signing_request).strip() for csr in existing_csrs
        }

        for csr in self.certificate_signing_requests:
            if str(csr).strip() not in existing_csr_strings:
                self._request_certificate(csr=csr, is_ca=False)
                logger.info(f"Sent CSR with common_name: {csr.common_name}")

    def get_assigned_certificates(self) -> List[ProviderCertificate]:
        """Get a list of certificates that were assigned to this unit."""
        assigned_certificates = []
        for requirer_csr in self.get_csrs_from_requirer_relation_data():
            if cert := self._find_certificate_in_relation_data(requirer_csr):
                assigned_certificates.append(cert)
        return assigned_certificates

    def _find_certificate_in_relation_data(
        self, csr: RequirerCertificateRequest
    ) -> Optional[ProviderCertificate]:
        """Return the certificate that matches the given CSR."""
        for provider_certificate in self.get_provider_certificates():
            if provider_certificate.certificate_signing_request == csr.certificate_signing_request:
                if provider_certificate.certificate.is_ca and not csr.is_ca:
                    logger.warning("Non CA certificate requested, got a CA certificate, ignoring")
                    continue
                if not provider_certificate.certificate.is_ca and csr.is_ca:
                    logger.warning("CA certificate requested, got a non CA certificate, ignoring")
                    continue
                return provider_certificate
        return None

    def _find_available_certificates(self):
        """Find available certificates and emit events.

        This method will find certificates that are available for the requirer's CSRs
        and emit events when they become available.
        """
        requirer_csrs = self.get_csrs_from_requirer_relation_data()
        csrs = [csr.certificate_signing_request for csr in requirer_csrs]
        provider_certificates = self.get_provider_certificates()

        for provider_certificate in provider_certificates:
            if provider_certificate.certificate_signing_request in csrs:
                if provider_certificate.revoked:
                    logger.info("Certificate revoked for CSR")
                    continue

                self.on.certificate_available.emit(
                    certificate_signing_request=provider_certificate.certificate_signing_request,
                    certificate=provider_certificate.certificate,
                    ca=provider_certificate.ca,
                    chain=provider_certificate.chain,
                )
                logger.info(
                    f"Certificate available for CSR with common_name: "
                    f"{provider_certificate.certificate_signing_request.common_name}"
                )

    def _remove_requirer_csr_from_relation_data(self, csr: CertificateSigningRequest) -> None:
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return
        if not self.get_csrs_from_requirer_relation_data():
            logger.info("No CSRs in relation data - Doing nothing")
            return
        try:
            requirer_relation_data = _RequirerData.load(relation.data[self.model.unit])
        except DataValidationError:
            logger.warning("Invalid relation data - Skipping removal of CSR")
            return
        new_relation_data = copy.deepcopy(requirer_relation_data.certificate_signing_requests)
        for requirer_csr in new_relation_data:
            if requirer_csr.certificate_signing_request.strip() == str(csr).strip():
                new_relation_data.remove(requirer_csr)
        try:
            _RequirerData(certificate_signing_requests=new_relation_data).dump(
                relation.data[self.model.unit]
            )
            logger.info("Removed CSR from relation data")
        except ModelError:
            logger.warning("Failed to update relation data")

    def _cleanup_certificate_requests(self):
        """Clean up certificate requests."""
        for requirer_csr in self.get_csrs_from_requirer_relation_data():
            self._remove_requirer_csr_from_relation_data(requirer_csr.certificate_signing_request)
            logger.info(
                "Removed CSR from relation data because it did not match any certificate request"  # noqa: E501
            )

    def _tls_relation_created(self) -> bool:
        """Check if TLS relation exists."""
        relation = self.model.get_relation(self.relationship_name)
        return relation is not None
