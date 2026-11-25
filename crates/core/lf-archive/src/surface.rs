//! High-level surface data structures for Daml-LF smart contracts and modules.
//!
//! Provides clean, serde-serializable representations of Daml templates, fields,
//! signatories, observers, choices, controllers, parameters, and byte-presence markers.
//! Designed for terminal rendering, JSON serialization, and downstream G2 type checking.

use serde::{Deserialize, Serialize};

/// High-level representation of Daml surface types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "details")]
pub enum SurfaceType {
    /// Daml Party identifier.
    Party,
    /// UTF-8 Text string.
    Text,
    /// Fixed-precision decimal number. Standard Daml `Decimal` has scale 10.
    Numeric(Option<u8>),
    /// 64-bit integer.
    Int64,
    /// Boolean value.
    Bool,
    /// Date value.
    Date,
    /// Microsecond Timestamp value.
    Timestamp,
    /// Unit type `()`.
    Unit,
    /// Active contract identifier: `ContractId T`.
    ContractId(Box<SurfaceType>),
    /// Homogeneous list: `List T`.
    List(Box<SurfaceType>),
    /// Optional value: `Optional T`.
    Optional(Box<SurfaceType>),
    /// General key-value map: `Map K V`.
    GenMap {
        key: Box<SurfaceType>,
        value: Box<SurfaceType>,
    },
    /// Product tuple: `(T1, T2, ...)`.
    Tuple(Vec<SurfaceType>),
    /// Nominal type constructor reference.
    TypeCon {
        package_id: Option<String>,
        module_name: Option<String>,
        name: String,
        args: Vec<SurfaceType>,
    },
    /// Type variable binder.
    TypeVar(String),
    /// Function arrow: `A -> B`.
    Arrow(Box<SurfaceType>, Box<SurfaceType>),
    /// Other uninterpreted Daml-LF types.
    Other(String),
}

impl SurfaceType {
    /// Returns the canonical human-readable Daml representation of this type.
    pub fn display_daml(&self) -> String {
        match self {
            SurfaceType::Party => "Party".to_string(),
            SurfaceType::Text => "Text".to_string(),
            SurfaceType::Numeric(Some(10)) | SurfaceType::Numeric(None) => "Decimal".to_string(),
            SurfaceType::Numeric(Some(scale)) => format!("Numeric {}", scale),
            SurfaceType::Int64 => "Int64".to_string(),
            SurfaceType::Bool => "Bool".to_string(),
            SurfaceType::Date => "Date".to_string(),
            SurfaceType::Timestamp => "Timestamp".to_string(),
            SurfaceType::Unit => "()".to_string(),
            SurfaceType::ContractId(inner) => format!("ContractId {}", inner.display_daml()),
            SurfaceType::List(inner) => format!("List {}", inner.display_daml()),
            SurfaceType::Optional(inner) => format!("Optional {}", inner.display_daml()),
            SurfaceType::GenMap { key, value } => {
                format!("Map {} {}", key.display_daml(), value.display_daml())
            }
            SurfaceType::Tuple(elems) => {
                if elems.is_empty() {
                    "()".to_string()
                } else {
                    let parts: Vec<String> = elems.iter().map(|e| e.display_daml()).collect();
                    format!("({})", parts.join(", "))
                }
            }
            SurfaceType::TypeCon { name, args, .. } => {
                if args.is_empty() {
                    name.clone()
                } else {
                    let parts: Vec<String> = args.iter().map(|a| a.display_daml()).collect();
                    format!("{} {}", name, parts.join(" "))
                }
            }
            SurfaceType::TypeVar(v) => v.clone(),
            SurfaceType::Arrow(arg, ret) => {
                format!("{} -> {}", arg.display_daml(), ret.display_daml())
            }
            SurfaceType::Other(s) => s.clone(),
        }
    }
}

/// A contract or record field definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDef {
    /// Field identifier.
    pub name: String,
    /// Structured type representation.
    pub ty: SurfaceType,
    /// Canonical Daml type string.
    pub type_str: String,
}

impl FieldDef {
    /// Creates a new field definition with formatted type string.
    pub fn new(name: impl Into<String>, ty: SurfaceType) -> Self {
        let type_str = ty.display_daml();
        Self {
            name: name.into(),
            ty,
            type_str,
        }
    }
}

/// A parameter passed to a contract choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChoiceParam {
    /// Parameter identifier.
    pub name: String,
    /// Structured type representation.
    pub ty: SurfaceType,
    /// Canonical Daml type string.
    pub type_str: String,
}

impl ChoiceParam {
    /// Creates a new choice parameter with formatted type string.
    pub fn new(name: impl Into<String>, ty: SurfaceType) -> Self {
        let type_str = ty.display_daml();
        Self {
            name: name.into(),
            ty,
            type_str,
        }
    }
}

/// Raw protobuf byte presence and length for unexecuted code blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytePresence {
    /// True if bytecode was present on the wire.
    pub present: bool,
    /// Byte length of the serialized expression.
    pub bytes_len: usize,
}

impl BytePresence {
    /// Constructs a presence marker indicating present bytecode.
    pub fn present(bytes_len: usize) -> Self {
        Self {
            present: true,
            bytes_len,
        }
    }

    /// Constructs an absent marker.
    pub fn absent() -> Self {
        Self {
            present: false,
            bytes_len: 0,
        }
    }
}

/// Surface definition of a contract choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChoiceDef {
    /// Choice name.
    pub name: String,
    /// Consuming mode.
    pub consuming: bool,
    /// Controller party expressions / field projections.
    pub controllers: Vec<String>,
    /// Observer party expressions / field projections.
    pub observers: Vec<String>,
    /// Parameters accepted by this choice.
    pub params: Vec<ChoiceParam>,
    /// Return type AST.
    pub return_type: SurfaceType,
    /// Canonical Daml return type string.
    pub return_type_str: String,
    /// Byte presence marker for choice execution body (`do` block).
    pub do_body: BytePresence,
}

/// Surface definition of a Daml smart contract template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateSurface {
    /// Template name.
    pub name: String,
    /// Template instance variable binder (e.g. "this").
    pub param_name: String,
    /// Contract fields defined in the template record.
    pub fields: Vec<FieldDef>,
    /// Signatory party fields.
    pub signatories: Vec<String>,
    /// Observer party fields.
    pub observers: Vec<String>,
    /// Choices available on this template.
    pub choices: Vec<ChoiceDef>,
    /// Byte presence marker for precondition assertion (`ensure` block).
    pub ensure: BytePresence,
}

/// Surface structure of an exported module in the main DALF package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleSurface {
    /// Module name.
    pub name: String,
    /// Contract templates defined in this module.
    pub templates: Vec<TemplateSurface>,
}
