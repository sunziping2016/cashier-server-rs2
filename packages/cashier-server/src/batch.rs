pub type ToSql = dyn tokio_postgres::types::ToSql + std::marker::Sync;

pub fn batch_values(item_num: usize, f: impl Fn(usize) -> String) -> String {
    (0..item_num)
        .enumerate()
        .map(|(i, _)| f(i))
        .map(|x| format!("({})", x))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn batch_slots(begin: usize, end: usize) -> String {
    (begin..end)
        .map(|x| format!("${}", x))
        .collect::<Vec<_>>()
        .join(",")
}