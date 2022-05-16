//! # Sparse VOLE Correlation PCG
//!
//! This module implements a PCG for the Sparse VOLE correlation.
//! Specifically this is the simplest form of a PCG from which various other correlations can be derived.
//! The scheme is based on the [Compressing Vector OLE](https://eprint.iacr.org/2019/273.pdf) paper by BCGI.
//! >  ⚠ **Notice**: This is a two-party correlation!
//!
//! In the beginning:
//!
//! - We have $q=p^k$ for some $k>1$.
//! - [PartyA] gives as input to the correlation functionality a *field* element $x \in \mathbb{F}^q$.
//! - [PartyB] gives as input to the correlation functionality a low-weight *subfield* vector $v \in \mathbb{F}^{p\times N}$ of weight $t$.
//!
//! The outut of the functionality yields both parties additive shares of $x\cdot v$.
//! This is done by [PartyB] sharing $t$ PPRFs with [PartyA].

pub struct PartyA {}

pub struct PartyB {}
