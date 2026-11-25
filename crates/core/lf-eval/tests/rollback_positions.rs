//! S-SPL-027: the positions of the nodes after a rolled-back `try` count the nodes inside it.
//!
//! A rollback takes no child index of its own, and the action nodes in it (fetches included) take the next indices of the exercise around it
//! (`PartialTransaction.rollbackTry`). The measurement behind this is a harness test (`canton-participant/tests/sequencer_connect.rs`,
//! `the_official_participant_confirms_a_create_that_comes_after_a_rollback_the_rust_participant_built`): the official participant approves a
//! request in which the create after a rollback holding two fetches has index 2. This test checks that the engine places that create the same way.
//!
//! Docker-free. The fixture is `contracts/fixtures/lookup/` (`Scratch.AttemptThenCreate`).

use lf_eval::{Engine, Value, World};
use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

fn dar() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/fixtures/lookup/target/lookup-view.dar")
}

#[test]
fn a_create_after_a_rolled_back_try_is_placed_after_the_nodes_in_it() {
    let world = World::open(&dar()).unwrap();
    let paths: Rc<RefCell<Vec<Vec<usize>>>> = Rc::new(RefCell::new(Vec::new()));
    let mut engine = Engine::new(&world);
    {
        let paths = Rc::clone(&paths);
        let mut n = 0usize;
        engine.set_contract_id_allocator(move |new: &lf_eval::NewContract<'_>| {
            n += 1;
            paths.borrow_mut().push(new.path.to_vec());
            format!("cid{n}")
        });
    }
    let scratch = Value::Record {
        tycon: Some("Lookup:Scratch".into()),
        fields: vec![("owner".into(), Value::Party("erin".into()))],
    };
    let id = engine
        .create_as(
            &["erin"],
            world.main_package_id(),
            "Lookup:Scratch",
            &scratch,
        )
        .unwrap();
    engine
        .exercise_as(
            &["erin"],
            &id,
            "AttemptThenCreate",
            &Value::Record {
                tycon: None,
                fields: vec![],
            },
        )
        .unwrap();
    // the root create has the empty path; the create in the choice comes after the rollback holding two fetches: index 2
    assert_eq!(*paths.borrow(), vec![Vec::<usize>::new(), vec![2]]);
    // the journal itself still forgets the rolled-back fetches, and the engine keeps them apart
    assert_eq!(engine.events().len(), 3); // the root create, the exercise and the create in it
    assert_eq!(engine.rolled_back().len(), 1);
    assert_eq!(engine.rolled_back()[0].events.len(), 2);
}
