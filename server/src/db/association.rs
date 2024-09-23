//! A table to describe which CIDRs another CIDR is allowed to peer with.
//!
//! A peer belongs to one parent CIDR, and can by default see all peers within that parent.

use shared::Association;
use std::ops::{Deref, DerefMut};

pub static CREATE_TABLE_SQL: &str = "CREATE TABLE associations (
      id         INTEGER PRIMARY KEY,
      cidr_id_1  INTEGER NOT NULL,
      cidr_id_2  INTEGER NOT NULL,
      UNIQUE(cidr_id_1, cidr_id_2),
      FOREIGN KEY (cidr_id_1)
         REFERENCES cidrs (id) 
            ON UPDATE RESTRICT
            ON DELETE RESTRICT,
      FOREIGN KEY (cidr_id_2)
         REFERENCES cidrs (id) 
            ON UPDATE RESTRICT
            ON DELETE RESTRICT
    )";

#[derive(Debug)]
pub struct DatabaseAssociation {
    pub inner: Association,
}

impl From<Association> for DatabaseAssociation {
    fn from(inner: Association) -> Self {
        Self { inner }
    }
}

impl Deref for DatabaseAssociation {
    type Target = Association;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for DatabaseAssociation {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
