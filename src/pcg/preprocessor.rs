use std::vec::IntoIter;

pub struct Preprocessor<T: Iterator> {
    vec_iter: IntoIter<T::Item>,
}

impl<T: Iterator> Preprocessor<T> {
    #[allow(clippy::needless_collect)]
    pub fn new(amount: usize, iter: T) -> Self {
        let v: Vec<_> = iter.take(amount).collect();
        Self {
            vec_iter: v.into_iter(),
        }
    }
}

impl<T: Iterator> Iterator for Preprocessor<T> {
    type Item = T::Item;
    fn next(&mut self) -> Option<Self::Item> {
        self.vec_iter.next()
    }
}
