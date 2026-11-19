# Security

## What counts as a vulnerability here

The job of this code is to refuse altered evidence. A security issue is anything that makes
it accept what it should refuse, for example:

- two different bundles that verify to the same root;
- a changed object, blob or edge that `verify_bundle.py` still accepts;
- a `check/1` whose stored facts differ from the rows yet pass;
- a chain that `verify_chain.py` accepts with a missing or substituted link;
- an encoding that two conforming implementations hash differently;
- a private path or host name that survives the minter's redaction and the leak scan.

A break of SHA-256 itself is out of scope.

## Reporting

Please report privately through GitHub: the repository's **Security** tab, then
**Report a vulnerability**. Include the smallest bundle or input that shows the problem and
the command you ran. Please do not open a public issue for an unfixed acceptance bug.

## What the protocol does not claim

A verified root shows that a bundle is complete, unaltered and internally consistent under
its published rules. It does not show that the sealed source bytes were honestly produced,
and an unsigned bundle carries no authorship. These are stated limits, not vulnerabilities;
see "What a root tells you, and what it does not" in the README.
