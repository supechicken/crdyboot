use crate::{Error, Generation, Result};
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use ascii::AsciiStr;
use core::ops::Range;
use csv_core::{ReadFieldResult, Reader};
use log::warn;

#[derive(Clone)]
struct ParseOpts {
    /// Maximum size in bytes of an individual CSV field.
    max_field_bytes: usize,

    /// Maximum number of records in a CSV.
    max_records: usize,

    /// Initial size of the output data allocation.
    initial_data_bytes: usize,
}

impl Default for ParseOpts {
    fn default() -> ParseOpts {
        ParseOpts {
            // The specific values set here are somewhat arbitrary, but
            // larger than would be expected in any reasonable input.
            max_field_bytes: 1024,
            max_records: 1024,

            // This should fit about a six-line SBAT file with typical
            // field lengths.
            initial_data_bytes: 512,
        }
    }
}

struct Parser<'a, const F: usize> {
    input: &'a [u8],
    output: Csv<F>,
    reader: Reader,
    opts: ParseOpts,
    record_closed: bool,
    max_data_bytes: usize,
    cur_field: Field,
}

impl<'a, const F: usize> Parser<'a, F> {
    fn new(input: &'a [u8], opts: ParseOpts) -> Parser<'a, F> {
        // Maximum size of `output.data`.
        let max_data_bytes = opts.max_records * F * opts.max_field_bytes;

        Parser {
            input,
            output: Csv {
                records: Vec::with_capacity(10),
                data: Vec::with_capacity(opts.initial_data_bytes),
            },
            reader: Reader::new(),
            opts,
            max_data_bytes,

            // Initially there is no existing record, so a new one must
            // be created.
            record_closed: true,
            cur_field: Field::default(),
        }
    }

    fn add_field(&mut self, field: Field) -> Result<()> {
        // Add the field to the current record, or start a
        // new record.
        if self.record_closed {
            if self.output.records.len() >= self.opts.max_records {
                return Err(Error::TooManyRecords);
            }

            let mut record = Record::default();
            record.add_field(field);
            self.output.records.push(record);

            self.record_closed = false;
        } else {
            // OK to unwrap since `self.record_closed` starts out true,
            // so at least one element is definitely in the vec at this
            // point.
            let last = self.output.records.last_mut().unwrap();
            last.add_field(field);
        }

        Ok(())
    }

    /// Increase the size of the `output.data` vec to accommodate
    /// additional output.
    ///
    /// This uses a simple doubling strategy, but capped to
    /// `self.max_data_bytes`. If the size is already at that maximum,
    /// `Error::TooMuchData` is returned.
    fn grow_data(&mut self) -> Result<()> {
        let cur_len = self.output.data.len();
        let mut new_len = cur_len * 2;
        if new_len == 0 {
            new_len = 32;
        }
        if new_len > self.max_data_bytes {
            new_len = self.max_data_bytes;
        }
        if new_len <= cur_len {
            return Err(Error::TooMuchData);
        }
        self.output.data.resize(new_len, 0u8);
        Ok(())
    }

    fn parse(&mut self) -> Result<()> {
        self.output.data.resize(self.opts.initial_data_bytes, 0u8);

        loop {
            let (result, num_read, num_written) = self.reader.read_field(
                self.input,
                &mut self.output.data[self.cur_field.end()..],
            );

            // Advance the input and output slices.
            self.input = &self.input[num_read..];
            self.cur_field.add_bytes(num_written);

            if self.cur_field.len() > self.opts.max_field_bytes {
                return Err(Error::FieldTooLarge);
            }

            match result {
                ReadFieldResult::InputEmpty => {}
                ReadFieldResult::OutputFull => self.grow_data()?,
                ReadFieldResult::Field { record_end } => {
                    self.add_field(self.cur_field.clone())?;
                    self.cur_field.reset(self.cur_field.end());

                    if record_end {
                        self.record_closed = true;
                    }
                }
                ReadFieldResult::End => break,
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Field(Range<usize>);

impl Field {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    fn end(&self) -> usize {
        self.0.end
    }

    fn add_bytes(&mut self, num: usize) {
        self.0.end += num
    }

    fn reset(&mut self, start: usize) {
        self.0 = start..start;
    }
}

#[derive(Debug, Default)]
pub struct Record<const F: usize>(ArrayVec<Field, F>);

impl<const F: usize> Record<F> {
    pub fn num_fields(&self) -> usize {
        self.0.len()
    }

    fn get_field<'a>(
        &self,
        field_offset: usize,
        csv: &'a Csv<F>,
    ) -> Option<&'a [u8]> {
        let field = self.0.get(field_offset)?;
        csv.data.get(field.0.clone())
    }

    /// Get the contents of the record's field at `field_offset` as an
    /// `AsciiStr`.
    pub fn get_field_as_ascii<'a>(
        &self,
        field_offset: usize,
        csv: &'a Csv<F>,
    ) -> Result<Option<&'a AsciiStr>> {
        if let Some(field) = self.get_field(field_offset, csv) {
            Ok(Some(
                AsciiStr::from_ascii(field).map_err(|_| Error::InvalidAscii)?,
            ))
        } else {
            Ok(None)
        }
    }

    /// Get the contents of the record's field at `field_offset` as a
    /// `Generation`.
    pub fn get_field_as_generation(
        &self,
        field_offset: usize,
        csv: &Csv<F>,
    ) -> Result<Option<Generation>> {
        let ascii = self.get_field_as_ascii(field_offset, csv)?;
        if let Some(ascii) = ascii {
            Ok(Some(Generation::from_ascii(ascii)?))
        } else {
            Ok(None)
        }
    }

    /// Add a field to the record if possible. If there is no more room,
    /// the error is logged but otherwise ignored. This behavior is used
    /// because SBAT only really cares about the first two fields per
    /// record, the other fields act as human-readable comments.
    fn add_field(&mut self, field: Field) {
        if self.0.try_push(field).is_err() {
            warn!("maximum fields per record exceeded");
        }
    }
}

pub struct Csv<const F: usize> {
    data: Vec<u8>,
    records: Vec<Record<F>>,
}

impl<const F: usize> Csv<F> {
    fn parse_with_opts(input: &[u8], opts: ParseOpts) -> Result<Self> {
        let mut parser = Parser::new(input, opts);

        parser.parse()?;

        Ok(parser.output)
    }

    pub fn parse(input: &[u8]) -> Result<Self> {
        Self::parse_with_opts(input, ParseOpts::default())
    }

    pub fn records(&self) -> &[Record<F>] {
        &self.records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_nested_vecs<const F: usize>(csv: &Csv<F>) -> Vec<Vec<String>> {
        csv.records()
            .iter()
            .map(|record| {
                (0..record.num_fields())
                    .map(|i| {
                        String::from_utf8(
                            record.get_field(i, csv).unwrap().to_vec(),
                        )
                        .unwrap()
                    })
                    .collect()
            })
            .collect()
    }

    fn parse_simple<const F: usize>(
        input: &str,
        opts: ParseOpts,
    ) -> Vec<Vec<String>> {
        let csv = Csv::<F>::parse_with_opts(input.as_bytes(), opts).unwrap();
        to_nested_vecs(&csv)
    }

    #[test]
    fn parse_success() {
        assert_eq!(
            parse_simple::<3>(
                "field1,field2,field3\na,b\n",
                ParseOpts::default()
            ),
            vec![vec!["field1", "field2", "field3"], vec!["a", "b"]]
        );
    }

    #[test]
    fn parse_error() {
        let input = b"field1,field2,field3\nd,e\n";

        assert_eq!(
            Csv::<3>::parse_with_opts(
                input,
                ParseOpts {
                    max_field_bytes: 6,
                    max_records: 1,
                    ..Default::default()
                },
            )
            .err()
            .unwrap(),
            Error::TooManyRecords
        );

        assert_eq!(
            Csv::<3>::parse_with_opts(
                input,
                ParseOpts {
                    max_field_bytes: 5,
                    max_records: 2,
                    ..Default::default()
                },
            )
            .err()
            .unwrap(),
            Error::FieldTooLarge
        );
    }

    /// Check that extra fields beyond the allowed amount per record are
    /// dropped without error.
    #[test]
    fn too_many_fields() {
        assert_eq!(
            parse_simple::<2>("a,b,c,d\n", ParseOpts::default()),
            vec![vec!["a", "b"]]
        );
    }

    /// Check that growing the data vec works.
    #[test]
    fn realloc_required() {
        let input = "reallylongfieldjustwaytoobigwowitjustkeepsgoing";

        let opts = ParseOpts {
            max_field_bytes: 47,
            max_records: 1,
            // This value is much smaller than the input size.
            initial_data_bytes: 2,
        };
        assert_eq!(parse_simple::<1>(input, opts), vec![vec![input]]);
    }

    /// Check that a final record with no trailing newline parses correctly.
    #[test]
    fn no_trailing_newline() {
        assert_eq!(
            parse_simple::<2>("a", ParseOpts::default()),
            vec![vec!["a"]]
        );
        assert_eq!(
            parse_simple::<2>("a\nb", ParseOpts::default()),
            vec![vec!["a"], vec!["b"]]
        );
        assert_eq!(
            parse_simple::<2>("a,b", ParseOpts::default()),
            vec![vec!["a", "b"]]
        );
        assert_eq!(
            parse_simple::<2>("ab,cd", ParseOpts::default()),
            vec![vec!["ab", "cd"]]
        );
    }

    /// Check that URL-like strings parse correctly.
    #[test]
    fn urls() {
        assert_eq!(
            parse_simple::<2>(
                "http://www.example.com/a.html,https://example.org\n",
                ParseOpts::default(),
            ),
            vec![vec!["http://www.example.com/a.html", "https://example.org"]]
        );
    }

    #[test]
    fn ascii_fields() {
        let csv = Csv::<2>::parse("a,😀\n".as_bytes()).unwrap();
        let record = &csv.records()[0];

        assert_eq!(
            record.get_field_as_ascii(0, &csv).unwrap(),
            Some(AsciiStr::from_ascii("a").unwrap())
        );
        assert_eq!(
            record.get_field_as_ascii(1, &csv).unwrap_err(),
            Error::InvalidAscii
        );
    }

    #[test]
    fn generation_fields() {
        let csv = Csv::<2>::parse("123,a\n".as_bytes()).unwrap();
        let record = &csv.records()[0];

        assert_eq!(
            record.get_field_as_generation(0, &csv).unwrap(),
            Some(Generation::new(123).unwrap())
        );
        assert_eq!(
            record.get_field_as_generation(1, &csv).unwrap_err(),
            Error::InvalidGeneration
        );
    }
}
