//! # Node Coded (forked from `substrate`)
//!
//! Custom node encoding/decoding for trie operations. **DO NOT TOUCH THIS!**.
//!
//! ```txt
//! This file is part of Substrate.
//!
//! Copyright (C) Parity Technologies (UK) Ltd.
//! SPDX-License-Identifier: Apache-2.0
//!
//! Licensed under the Apache License, Version 2.0 (the "License");
//! you may not use this file except in compliance with the License.
//! You may obtain a copy of the License at
//!
//!   http://www.apache.org/licenses/LICENSE-2.0
//!
//! Unless required by applicable law or agreed to in writing, software
//! distributed under the License is distributed on an "AS IS" BASIS,
//! WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//! See the License for the specific language governing permissions and
//! limitations under the License.
//! ```
use codec::{Compact, Decode, Encode, Input, Output};
use core::iter::once;
use std::{
    borrow::Borrow,
    fmt::{Debug, Display},
    marker::PhantomData,
    ops::Range,
};
use trie_db::{
    ChildReference, Hasher, NodeCodec as NodeCodecT, nibble_ops,
    node::{NibbleSlicePlan, NodeHandlePlan, NodePlan, Value, ValuePlan},
};

const BITMAP_LENGTH: usize = 2;

/// Constants used into trie simplification codec.
mod trie_constants {
    const FIRST_PREFIX: u8 = 0b_00 << 6;
    pub const LEAF_PREFIX_MASK: u8 = 0b_01 << 6;
    pub const BRANCH_WITHOUT_MASK: u8 = 0b_10 << 6;
    pub const BRANCH_WITH_MASK: u8 = 0b_11 << 6;
    pub const EMPTY_TRIE: u8 = FIRST_PREFIX | (0b_00 << 4);
    pub const ALT_HASHING_LEAF_PREFIX_MASK: u8 = FIRST_PREFIX | (0b_1 << 5);
    pub const ALT_HASHING_BRANCH_WITH_MASK: u8 = FIRST_PREFIX | (0b_01 << 4);
    pub const ESCAPE_COMPACT_HEADER: u8 = EMPTY_TRIE | 0b_00_01;
}

/// Error type used for trie related errors.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Error {
    BadFormat,
    Decode(codec::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadFormat => write!(f, "bad format"),
            Error::Decode(err) => write!(f, "decode error: {}", err),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Decode(err) => Some(err),
            Error::BadFormat => None,
        }
    }
}

impl From<codec::Error> for Error {
    fn from(err: codec::Error) -> Self {
        Error::Decode(err)
    }
}

/// Concrete implementation of a [`NodeCodecT`] with SCALE encoding.
///
/// It is generic over `H` the [`Hasher`].
#[derive(Default, Clone)]
pub struct NodeCodec<H>(PhantomData<H>);

impl<H> NodeCodecT for NodeCodec<H>
where
    H: Hasher,
{
    const ESCAPE_HEADER: Option<u8> = Some(trie_constants::ESCAPE_COMPACT_HEADER);
    type Error = Error;
    type HashOut = H::Out;

    fn hashed_null_node() -> <H as Hasher>::Out {
        H::hash(<Self as NodeCodecT>::empty_node())
    }

    fn decode_plan(data: &[u8]) -> Result<NodePlan, Self::Error> {
        let mut input = ByteSliceInput::new(data);

        let header = NodeHeader::decode(&mut input)?;
        let contains_hash = header.contains_hash_of_value();

        let branch_has_value = if let NodeHeader::Branch(has_value, _) = &header {
            *has_value
        } else {
            // hashed_value_branch
            true
        };

        match header {
            NodeHeader::Null => Ok(NodePlan::Empty),
            NodeHeader::HashedValueBranch(nibble_count) | NodeHeader::Branch(_, nibble_count) => {
                let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
                // data should be at least of size offset + 1
                if data.len() < input.offset + 1 {
                    return Err(Error::BadFormat);
                }
                // check that the padding is valid (if any)
                if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
                    return Err(Error::BadFormat);
                }
                let partial = input.take(nibble_count.div_ceil(nibble_ops::NIBBLE_PER_BYTE))?;
                let partial_padding = nibble_ops::number_padding(nibble_count);
                let bitmap_range = input.take(BITMAP_LENGTH)?;
                let bitmap = Bitmap::decode(&data[bitmap_range])?;
                let value = if branch_has_value {
                    Some(if contains_hash {
                        ValuePlan::Node(input.take(H::LENGTH)?)
                    } else {
                        let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
                        ValuePlan::Inline(input.take(count)?)
                    })
                } else {
                    None
                };
                let mut children = [
                    None, None, None, None, None, None, None, None, None, None, None, None, None,
                    None, None, None,
                ];
                for i in 0..nibble_ops::NIBBLE_LENGTH {
                    if bitmap.value_at(i) {
                        let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
                        let range = input.take(count)?;
                        children[i] = Some(if count == H::LENGTH {
                            NodeHandlePlan::Hash(range)
                        } else {
                            NodeHandlePlan::Inline(range)
                        });
                    }
                }
                Ok(NodePlan::NibbledBranch {
                    partial: NibbleSlicePlan::new(partial, partial_padding),
                    value,
                    children,
                })
            }
            NodeHeader::HashedValueLeaf(nibble_count) | NodeHeader::Leaf(nibble_count) => {
                let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
                // data should be at least of size offset + 1
                if data.len() < input.offset + 1 {
                    return Err(Error::BadFormat);
                }
                // check that the padding is valid (if any)
                if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
                    return Err(Error::BadFormat);
                }
                let partial = input.take(nibble_count.div_ceil(nibble_ops::NIBBLE_PER_BYTE))?;
                let partial_padding = nibble_ops::number_padding(nibble_count);
                let value = if contains_hash {
                    ValuePlan::Node(input.take(H::LENGTH)?)
                } else {
                    let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
                    ValuePlan::Inline(input.take(count)?)
                };

                Ok(NodePlan::Leaf {
                    partial: NibbleSlicePlan::new(partial, partial_padding),
                    value,
                })
            }
        }
    }

    fn is_empty_node(data: &[u8]) -> bool {
        data == <Self as NodeCodecT>::empty_node()
    }

    fn empty_node() -> &'static [u8] {
        &[trie_constants::EMPTY_TRIE]
    }

    fn leaf_node(partial: impl Iterator<Item = u8>, number_nibble: usize, value: Value) -> Vec<u8> {
        let contains_hash = matches!(&value, Value::Node(..));
        let mut output = if contains_hash {
            partial_from_iterator_encode(partial, number_nibble, NodeKind::HashedValueLeaf)
        } else {
            partial_from_iterator_encode(partial, number_nibble, NodeKind::Leaf)
        };
        match value {
            Value::Inline(value) => {
                Compact(value.len() as u32).encode_to(&mut output);
                output.extend_from_slice(value);
            }
            Value::Node(hash) => {
                debug_assert!(hash.len() == H::LENGTH);
                output.extend_from_slice(hash);
            }
        }
        output
    }

    fn extension_node(
        _partial: impl Iterator<Item = u8>,
        _nbnibble: usize,
        _child: ChildReference<<H as Hasher>::Out>,
    ) -> Vec<u8> {
        unreachable!("No extension codec.")
    }

    fn branch_node(
        _children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out>>>>,
        _maybe_value: Option<Value>,
    ) -> Vec<u8> {
        unreachable!("No extension codec.")
    }

    fn branch_node_nibbled(
        partial: impl Iterator<Item = u8>,
        number_nibble: usize,
        children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out>>>>,
        value: Option<Value>,
    ) -> Vec<u8> {
        let contains_hash = matches!(&value, Some(Value::Node(..)));
        let mut output = match (&value, contains_hash) {
            (&None, _) => {
                partial_from_iterator_encode(partial, number_nibble, NodeKind::BranchNoValue)
            }
            (_, false) => {
                partial_from_iterator_encode(partial, number_nibble, NodeKind::BranchWithValue)
            }
            (_, true) => {
                partial_from_iterator_encode(partial, number_nibble, NodeKind::HashedValueBranch)
            }
        };

        let bitmap_index = output.len();
        let mut bitmap: [u8; BITMAP_LENGTH] = [0; BITMAP_LENGTH];
        (0..BITMAP_LENGTH).for_each(|_| output.push(0));
        match value {
            Some(Value::Inline(value)) => {
                Compact(value.len() as u32).encode_to(&mut output);
                output.extend_from_slice(value);
            }
            Some(Value::Node(hash)) => {
                debug_assert!(hash.len() == H::LENGTH);
                output.extend_from_slice(hash);
            }
            None => (),
        }
        Bitmap::encode(
            children.map(|maybe_child| match maybe_child.borrow() {
                Some(ChildReference::Hash(h)) => {
                    h.as_ref().encode_to(&mut output);
                    true
                }
                &Some(ChildReference::Inline(inline_data, len)) => {
                    inline_data.as_ref()[..len].encode_to(&mut output);
                    true
                }
                None => false,
            }),
            bitmap.as_mut(),
        );
        output[bitmap_index..bitmap_index + BITMAP_LENGTH]
            .copy_from_slice(&bitmap[..BITMAP_LENGTH]);
        output
    }
}

/// A node header
#[derive(Copy, Clone, PartialEq, Eq)]
enum NodeHeader {
    Null,
    // contains wether there is a value and nibble count
    Branch(bool, usize),
    // contains nibble count
    Leaf(usize),
    // contains nibble count.
    HashedValueBranch(usize),
    // contains nibble count.
    HashedValueLeaf(usize),
}

impl NodeHeader {
    fn contains_hash_of_value(&self) -> bool {
        matches!(
            self,
            NodeHeader::HashedValueBranch(_) | NodeHeader::HashedValueLeaf(_)
        )
    }
}

/// NodeHeader without content
enum NodeKind {
    Leaf,
    BranchNoValue,
    BranchWithValue,
    HashedValueLeaf,
    HashedValueBranch,
}

impl Encode for NodeHeader {
    fn encode_to<T: Output + ?Sized>(&self, output: &mut T) {
        match self {
            NodeHeader::Null => output.push_byte(trie_constants::EMPTY_TRIE),
            NodeHeader::Branch(true, nibble_count) => {
                encode_size_and_prefix(*nibble_count, trie_constants::BRANCH_WITH_MASK, 2, output)
            }
            NodeHeader::Branch(false, nibble_count) => encode_size_and_prefix(
                *nibble_count,
                trie_constants::BRANCH_WITHOUT_MASK,
                2,
                output,
            ),
            NodeHeader::Leaf(nibble_count) => {
                encode_size_and_prefix(*nibble_count, trie_constants::LEAF_PREFIX_MASK, 2, output)
            }
            NodeHeader::HashedValueBranch(nibble_count) => encode_size_and_prefix(
                *nibble_count,
                trie_constants::ALT_HASHING_BRANCH_WITH_MASK,
                4,
                output,
            ),
            NodeHeader::HashedValueLeaf(nibble_count) => encode_size_and_prefix(
                *nibble_count,
                trie_constants::ALT_HASHING_LEAF_PREFIX_MASK,
                3,
                output,
            ),
        }
    }
}

impl codec::EncodeLike for NodeHeader {}

impl Decode for NodeHeader {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let i = input.read_byte()?;
        if i == trie_constants::EMPTY_TRIE {
            return Ok(NodeHeader::Null);
        }
        match i & (0b11 << 6) {
            trie_constants::LEAF_PREFIX_MASK => Ok(NodeHeader::Leaf(decode_size(i, input, 2)?)),
            trie_constants::BRANCH_WITH_MASK => {
                Ok(NodeHeader::Branch(true, decode_size(i, input, 2)?))
            }
            trie_constants::BRANCH_WITHOUT_MASK => {
                Ok(NodeHeader::Branch(false, decode_size(i, input, 2)?))
            }
            trie_constants::EMPTY_TRIE => {
                if i & (0b111 << 5) == trie_constants::ALT_HASHING_LEAF_PREFIX_MASK {
                    Ok(NodeHeader::HashedValueLeaf(decode_size(i, input, 3)?))
                } else if i & (0b1111 << 4) == trie_constants::ALT_HASHING_BRANCH_WITH_MASK {
                    Ok(NodeHeader::HashedValueBranch(decode_size(i, input, 4)?))
                } else {
                    // do not allow any special encoding
                    Err("Unallowed encoding".into())
                }
            }
            _ => unreachable!(),
        }
    }
}

/// Returns an iterator over encoded bytes for node header and size.
/// Size encoding allows unlimited, length inefficient, representation, but
/// is bounded to 16 bit maximum value to avoid possible DOS.
fn size_and_prefix_iterator(
    size: usize,
    prefix: u8,
    prefix_mask: usize,
) -> impl Iterator<Item = u8> {
    let max_value = 255u8 >> prefix_mask;
    let l1 = core::cmp::min((max_value as usize).saturating_sub(1), size);
    let (first_byte, mut rem) = if size == l1 {
        (once(prefix + l1 as u8), 0)
    } else {
        (once(prefix + max_value as u8), size - l1)
    };
    let next_bytes = move || {
        if rem > 0 {
            if rem < 256 {
                let result = rem - 1;
                rem = 0;
                Some(result as u8)
            } else {
                rem = rem.saturating_sub(255);
                Some(255)
            }
        } else {
            None
        }
    };
    first_byte.chain(core::iter::from_fn(next_bytes))
}

/// Encodes size and prefix to a stream output.
fn encode_size_and_prefix<W>(size: usize, prefix: u8, prefix_mask: usize, out: &mut W)
where
    W: Output + ?Sized,
{
    for b in size_and_prefix_iterator(size, prefix, prefix_mask) {
        out.push_byte(b)
    }
}

/// Decode size only from stream input and header byte.
fn decode_size(
    first: u8,
    input: &mut impl Input,
    prefix_mask: usize,
) -> Result<usize, codec::Error> {
    let max_value = 255u8 >> prefix_mask;
    let mut result = (first & max_value) as usize;
    if result < max_value as usize {
        return Ok(result);
    }
    result -= 1;
    loop {
        let n = input.read_byte()? as usize;
        if n < 255 {
            return Ok(result + n + 1);
        }
        result += 255;
    }
}

/// Encode and allocate node type header (type and size), and partial value.
/// It uses an iterator over encoded partial bytes as input.
fn partial_from_iterator_encode<I: Iterator<Item = u8>>(
    partial: I,
    nibble_count: usize,
    node_kind: NodeKind,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(4 + (nibble_count / nibble_ops::NIBBLE_PER_BYTE));
    match node_kind {
        NodeKind::Leaf => NodeHeader::Leaf(nibble_count).encode_to(&mut output),
        NodeKind::BranchWithValue => NodeHeader::Branch(true, nibble_count).encode_to(&mut output),
        NodeKind::BranchNoValue => NodeHeader::Branch(false, nibble_count).encode_to(&mut output),
        NodeKind::HashedValueLeaf => {
            NodeHeader::HashedValueLeaf(nibble_count).encode_to(&mut output)
        }
        NodeKind::HashedValueBranch => {
            NodeHeader::HashedValueBranch(nibble_count).encode_to(&mut output)
        }
    };
    output.extend(partial);
    output
}

/// Helper struct for trie node decoder. This implements `codec::Input` on a byte slice, while
/// tracking the absolute position. This is similar to `std::io::Cursor` but does not implement
/// `Read` and `io` are not in `core` or `alloc`.
struct ByteSliceInput<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ByteSliceInput<'a> {
    fn new(data: &'a [u8]) -> Self {
        ByteSliceInput { data, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<Range<usize>, codec::Error> {
        if self.offset + count > self.data.len() {
            return Err("out of data".into());
        }

        let range = self.offset..(self.offset + count);
        self.offset += count;
        Ok(range)
    }
}

impl<'a> Input for ByteSliceInput<'a> {
    fn remaining_len(&mut self) -> Result<Option<usize>, codec::Error> {
        Ok(Some(self.data.len().saturating_sub(self.offset)))
    }

    fn read(&mut self, into: &mut [u8]) -> Result<(), codec::Error> {
        let range = self.take(into.len())?;
        into.copy_from_slice(&self.data[range]);
        Ok(())
    }

    fn read_byte(&mut self) -> Result<u8, codec::Error> {
        if self.offset + 1 > self.data.len() {
            return Err("out of data".into());
        }

        let byte = self.data[self.offset];
        self.offset += 1;
        Ok(byte)
    }
}

/// Radix 16 trie, bitmap encoding implementation,
/// it contains children mapping information for a branch
/// (children presence only), it encodes into
/// a compact bitmap encoding representation.
struct Bitmap(u16);

impl Bitmap {
    fn decode(data: &[u8]) -> Result<Self, codec::Error> {
        let value = u16::decode(&mut &data[..])?;
        if value == 0 {
            Err("Bitmap without a child.".into())
        } else {
            Ok(Bitmap(value))
        }
    }

    fn value_at(&self, i: usize) -> bool {
        self.0 & (1u16 << i) != 0
    }

    fn encode<I: Iterator<Item = bool>>(has_children: I, dest: &mut [u8]) {
        let mut bitmap: u16 = 0;
        let mut cursor: u16 = 1;
        for v in has_children {
            if v {
                bitmap |= cursor
            }
            cursor <<= 1;
        }
        dest[0] = (bitmap % 256) as u8;
        dest[1] = (bitmap / 256) as u8;
    }
}
