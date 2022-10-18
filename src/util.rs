/// Convert a slice into array
///
/// # Arguments
///
/// * `slice` - slice to be converted
///
pub fn to_arr<A, T>(slice: &[T]) -> A
where
    A: AsMut<[T]> + Default,
    T: Clone,
{
    let mut arr = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut arr).clone_from_slice(slice);
    arr
}
