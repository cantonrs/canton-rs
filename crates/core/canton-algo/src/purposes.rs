pub struct HashPurpose {
    pub id: i32,
    pub scala_name: &'static str,
    pub description: &'static str,
}

pub static PURPOSES: &[HashPurpose] = &[
    HashPurpose {
        id: 1,
        scala_name: "SequencedEventSignature",
        description: "SequencedEventSignature",
    },
    HashPurpose {
        id: 2,
        scala_name: "_Hmac",
        description: "Hmac",
    },
    HashPurpose {
        id: 3,
        scala_name: "MerkleTreeInnerNode",
        description: "MerkleTreeInnerNode",
    },
    HashPurpose {
        id: 4,
        scala_name: "_Discriminator",
        description: "Discriminator",
    },
    HashPurpose {
        id: 5,
        scala_name: "SubmitterMetadata",
        description: "SubmitterMetadata",
    },
    HashPurpose {
        id: 6,
        scala_name: "CommonMetadata",
        description: "CommonMetadata",
    },
    HashPurpose {
        id: 7,
        scala_name: "ParticipantMetadata",
        description: "ParticipantMetadata",
    },
    HashPurpose {
        id: 8,
        scala_name: "ViewCommonData",
        description: "ViewCommonData",
    },
    HashPurpose {
        id: 9,
        scala_name: "ViewParticipantData",
        description: "ViewParticipantData",
    },
    HashPurpose {
        id: 10,
        scala_name: "_MalformedMediatorRequestResult",
        description: "MalformedMediatorRequestResult",
    },
    HashPurpose {
        id: 11,
        scala_name: "TopologyTransactionSignature",
        description: "TopologyTransactionSignature",
    },
    HashPurpose {
        id: 12,
        scala_name: "PublicKeyFingerprint",
        description: "PublicKeyFingerprint",
    },
    HashPurpose {
        id: 13,
        scala_name: "_DarIdentifier",
        description: "DarIdentifier",
    },
    HashPurpose {
        id: 14,
        scala_name: "AuthenticationToken",
        description: "AuthenticationToken",
    },
    HashPurpose {
        id: 15,
        scala_name: "_AgreementId",
        description: "AgreementId",
    },
    HashPurpose {
        id: 16,
        scala_name: "_MediatorResponseSignature",
        description: "MediatorResponseSignature",
    },
    HashPurpose {
        id: 17,
        scala_name: "_TransactionResultSignature",
        description: "TransactionResultSignature",
    },
    HashPurpose {
        id: 19,
        scala_name: "_TransferResultSignature",
        description: "TransferResultSignature",
    },
    HashPurpose {
        id: 20,
        scala_name: "_ParticipantStateSignature",
        description: "ParticipantStateSignature",
    },
    HashPurpose {
        id: 21,
        scala_name: "_SynchronizerTopologyTransactionMessageSignature",
        description: "SynchronizerTopologyTransactionMessageSignature",
    },
    HashPurpose {
        id: 22,
        scala_name: "AcsCommitment",
        description: "AcsCommitment",
    },
    HashPurpose {
        id: 23,
        scala_name: "Stakeholders",
        description: "Stakeholders",
    },
    HashPurpose {
        id: 24,
        scala_name: "UnassignmentCommonData",
        description: "UnassignmentCommonData",
    },
    HashPurpose {
        id: 25,
        scala_name: "UnassignmentView",
        description: "UnassignmentView",
    },
    HashPurpose {
        id: 26,
        scala_name: "AssignmentCommonData",
        description: "AssignmentCommonData",
    },
    HashPurpose {
        id: 27,
        scala_name: "AssignmentView",
        description: "AssignmentView",
    },
    HashPurpose {
        id: 28,
        scala_name: "_TransferViewTreeMessageSeed",
        description: "TransferViewTreeMessageSeed",
    },
    HashPurpose {
        id: 29,
        scala_name: "Unicum",
        description: "Unicum",
    },
    HashPurpose {
        id: 30,
        scala_name: "RepairUpdateId",
        description: "RepairUpdateId",
    },
    HashPurpose {
        id: 31,
        scala_name: "_MediatorLeadershipEvent",
        description: "MediatorLeadershipEvent",
    },
    HashPurpose {
        id: 32,
        scala_name: "_LegalIdentityClaim",
        description: "LegalIdentityClaim",
    },
    HashPurpose {
        id: 33,
        scala_name: "DbLockId",
        description: "DbLockId",
    },
    HashPurpose {
        id: 34,
        scala_name: "HashedAcsCommitment",
        description: "HashedAcsCommitment",
    },
    HashPurpose {
        id: 35,
        scala_name: "SubmissionRequestSignature",
        description: "SubmissionRequestSignature",
    },
    HashPurpose {
        id: 36,
        scala_name: "AcknowledgementSignature",
        description: "AcknowledgementSignature",
    },
    HashPurpose {
        id: 37,
        scala_name: "DecentralizedNamespaceNamespace",
        description: "DecentralizedNamespace",
    },
    HashPurpose {
        id: 38,
        scala_name: "SignedProtocolMessageSignature",
        description: "SignedProtocolMessageSignature",
    },
    HashPurpose {
        id: 39,
        scala_name: "AggregationId",
        description: "AggregationId",
    },
    HashPurpose {
        id: 40,
        scala_name: "BftOrderingPbftBlock",
        description: "BftOrderingPbftBlock",
    },
    HashPurpose {
        id: 41,
        scala_name: "_SetTrafficPurchased",
        description: "SetTrafficPurchased",
    },
    HashPurpose {
        id: 42,
        scala_name: "OrderingRequestSignature",
        description: "OrderingRequestSignature",
    },
    HashPurpose {
        id: 43,
        scala_name: "TopologyMappingUniqueKey",
        description: "TopologyMappingUniqueKey",
    },
    HashPurpose {
        id: 44,
        scala_name: "CantonScript",
        description: "CantonScriptHash",
    },
    HashPurpose {
        id: 45,
        scala_name: "BftAvailabilityAck",
        description: "BftAvailabilityAck",
    },
    HashPurpose {
        id: 46,
        scala_name: "BftBatchId",
        description: "BftBatchId",
    },
    HashPurpose {
        id: 47,
        scala_name: "BftSignedAvailabilityMessage",
        description: "BftSignedAvailabilityMessage",
    },
    HashPurpose {
        id: 48,
        scala_name: "PreparedSubmission",
        description: "PreparedSubmission",
    },
    HashPurpose {
        id: 49,
        scala_name: "TopologyUpdateId",
        description: "TopologyUpdateId",
    },
    HashPurpose {
        id: 50,
        scala_name: "OnlinePartyReplicationId",
        description: "OnlinePartyReplication",
    },
    HashPurpose {
        id: 51,
        scala_name: "PartyUpdateId",
        description: "PartyUpdateId",
    },
    HashPurpose {
        id: 52,
        scala_name: "BftSignedConsensusMessage",
        description: "BftSignedConsensusMessage",
    },
    HashPurpose {
        id: 53,
        scala_name: "BftSignedStateTransferMessage",
        description: "BftSignedStateTransferMessage",
    },
    HashPurpose {
        id: 54,
        scala_name: "BftSignedRetransmissionMessage",
        description: "BftSignedRetransmissionMessage",
    },
    HashPurpose {
        id: 55,
        scala_name: "MultiTopologyTransaction",
        description: "MultiTopologyTransaction",
    },
    HashPurpose {
        id: 56,
        scala_name: "SessionKeyDelegation",
        description: "SessionKeyDelegation",
    },
    HashPurpose {
        id: 57,
        scala_name: "ReassignmentId",
        description: "ReassignmentId",
    },
    HashPurpose {
        id: 58,
        scala_name: "EncryptedSessionKey",
        description: "EncryptedSessionKey",
    },
    HashPurpose {
        id: 59,
        scala_name: "ContractIdAbsolutization",
        description: "ContractIdAbsolutization",
    },
    HashPurpose {
        id: 60,
        scala_name: "InitialTopologyStateConsistency",
        description: "InitialTopologyStateConsistency",
    },
    HashPurpose {
        id: 61,
        scala_name: "AcsContinuationToken",
        description: "AcsContinuationToken",
    },
    HashPurpose {
        id: 62,
        scala_name: "LsuSequencingTestMessageContent",
        description: "LsuSequencingTestMessageContent",
    },
    HashPurpose {
        id: 63,
        scala_name: "UpdatesPageToken",
        description: "UpdatesPageToken",
    },
    HashPurpose {
        id: 64,
        scala_name: "CiphertextId",
        description: "CiphertextId",
    },
    HashPurpose {
        id: 65,
        scala_name: "SequencerAggregatorAggregation",
        description: "SequencerAggregatorAggregation",
    },
    HashPurpose {
        id: 66,
        scala_name: "AcsCommitmentUpdateId",
        description: "AcsCommitmentUpdateId",
    },
    HashPurpose {
        id: 67,
        scala_name: "AcsCommitmentSummary",
        description: "AcsCommitmentSummary",
    },
    HashPurpose {
        id: 68,
        scala_name: "AcsReplicationDigest",
        description: "AcsReplicationDigest",
    },
    HashPurpose {
        id: 69,
        scala_name: "Transparency",
        description: "ViewEncryptionTransparency",
    },
];
