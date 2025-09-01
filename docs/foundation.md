# The Foundation Layer

While the specifics of Botanix's fully federated multisig system remain a work in progress, we can already identify the critical properties that must be verified and guaranteed to ensure both correctness and security. The most important aspect is that much of the coordination and validation occurs off-chain in an asynchronous manner. Although users initiate pegouts deterministically through the EVM, the multisig system must handle complex, time-distributed operations: initiating signing rounds, exchanging multiple FROST packages across undefined timelines, and potentially employing batching systems that collect multiple pegouts before constructing PSBT transactions. Furthermore, PSBT transactions may fail or become orphaned on the Bitcoin layer, requiring pending pegouts to be nullified and made spendable again. These moving parts operate on different schedules, and we cannot expect these events to occur simultaneously for all observers. Additionally, validators - who may participate in zero, one, or multiple multisig accounts - cannot reliably track the constantly changing states of all other multisig accounts.

The Foundation Layer serves as a thin state verification layer that manages these critical properties without the complexity of tracking states across a constantly evolving landscape of validator set transitions, multisig account changes, rotations, and a dynamic Bitcoin chain where blocks may be orphaned. Following principles similar to the Trusted Execution Machine, the Foundation Layer treats all input as potentially malicious, verifies input through cryptographic proofs, and crucially makes all decisions based solely on provided inputs without requiring access to external networks or resources.

<div align="center">
<img src="assets/foundation_overview.png" alt="Foundation Layer Overview" width="100%">
</div>

## Representative System and Block Producer Coordination

Since Foundation Layer messages are included in the Non-Deterministic Data (NDD), CometBFT's block producer selection mechanism determines when and how multisig operations are coordinated. When a validator is selected as block producer, they temporarily act as a **representative** for one or more multisig accounts during that block's production cycle. This relationship is inherently subjective - the same block producer may represent multiple accounts simultaneously, and different accounts may be represented by different validators across blocks.

The representative system operates under a fairness assumption where block producers provide equal opportunity for all accounts they represent, though this fairness is not cryptographically enforced. Since representatives have discretionary power over which operations to include in their blocks, they could potentially favor certain accounts or operations over others. However, the broader CometBFT consensus mechanism ensures that no single validator can consistently monopolize block production.

A critical security consideration is that representatives may be malicious and could attempt to submit operations that result in penalties or equivocations for other multisig participants (a form of sabotage). To prevent this attack vector, any operation that could potentially cause negative consequences for other validators must include cryptographic signatures from those affected parties. This requirement ensures that malicious representatives cannot unilaterally commit honest validators to actions they did not authorize, maintaining the integrity of the multisig coordination process even when block producers are compromised.

## Architecture

<div align="center">
<img src="assets/foundation_module_system.png" alt="Foundation Module System" width="100%">
</div>

_Work-in-Progress..._
