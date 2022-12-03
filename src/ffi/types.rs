use serde::Serialize;
use typed_builder::TypedBuilder;

#[derive(Serialize)]
pub enum MsgType {
    Ecdhx,
    EcdsaSign,
    TaggedKdf,
    ConcatKdf,
}

#[derive(Serialize, TypedBuilder)]
#[serde(rename_all = "camelCase")]
pub struct Ecdhx {
    #[serde(rename = "type")]
    #[builder(default=MsgType::Ecdhx)]
    pub t: MsgType,
    pub private_key: String,
    pub public_key: String,
}

// TODO default value, into str
#[derive(Serialize, TypedBuilder)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaSign {
    #[serde(rename = "type")]
    #[builder(default=MsgType::EcdsaSign)]
    pub t: MsgType,
    pub ephemeral_private_key: String,
    pub msg: String,
}

#[derive(Serialize, TypedBuilder)]
#[serde(rename_all = "camelCase")]
pub struct TaggedKdf {
    #[serde(rename = "type")]
    #[builder(default=MsgType::TaggedKdf)]
    pub t: MsgType,

    pub msg: String,
    pub remote_public_key: String,
    pub mac_data: String,
}

#[derive(Serialize, TypedBuilder)]
#[serde(rename_all = "camelCase")]
pub struct ConcatKdf {
    #[serde(rename = "type")]
    #[builder(default=MsgType::ConcatKdf)]
    pub t: MsgType,
    pub private_key: String,
    pub msg: String,
}
