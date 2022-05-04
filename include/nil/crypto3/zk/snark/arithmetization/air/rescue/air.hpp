/*
  Implements an AIR for the Rescue hash chain claim:
    "I know a sequence of inputs {w_i} such that H(...H(H(w_0, w_1), w_2) ..., w_n) = p",
  where H is the Rescue hash function, {w_i} are 4-tuples of field elements, and p is the public
  output of the hash (which consists of 4 field elements).

  The Rescue trace consists of 12 columns, corresponding to the 12 field elements of the state.
  The hashes are computed in batches of 3 hashes that fit into 32 rows as follows:
  Row 0:
      The state of the computation in the beginning of the first hash (8 input field elements
      and 4 zeroes).
  Rows 1 to 10:
      The state of the computation in the middle of every Rescue round of the first hash.
  Rows 11 to 20:
      The state of the computation in the middle of every Rescue round of the second hash.
  Rows 21 to 30:
      The state of the computation in the middle of every Rescue round of the third hash.
  Row 31:
      The state of the computation in the end of the third third hash. The first 4 field elements in
      this state are the output.
*/
#ifndef STARKWARE_AIR_RESCUE_RESCUE_AIR_H_
#define STARKWARE_AIR_RESCUE_RESCUE_AIR_H_

#include <array>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "third_party/gsl/gsl-lite.hpp"

#include "starkware/air/air.h"
#include "starkware/air/rescue/rescue_constants.h"
#include "starkware/air/trace.h"
#include "starkware/algebra/field_operations.h"
#include "starkware/error_handling/error_handling.h"
#include "starkware/math/math.h"

namespace starkware {

    class RescueAir : public Air {
    public:
        static_assert(BaseFieldElement::FieldSize() % 3 == 2, "Base field must not have a third root of unity.");
        static constexpr uint64_t kCubeInverseExponent =
            SafeDiv((2 * BaseFieldElement::FieldSize() - 1), 3);    // = (1/3) % (kModulus - 1).
        static constexpr size_t kWordSize = 4;
        static constexpr size_t kHashesPerBatch = 3;
        static constexpr size_t kStateSize = RescueConstants::kStateSize;
        static constexpr size_t kNumRounds = RescueConstants::kNumRounds;
        static constexpr size_t kBatchHeight = RescueConstants::kBatchHeight;
        static constexpr size_t kNumColumns = kStateSize;
        static constexpr size_t kNumPeriodicColumns = 2 * kStateSize;
        static constexpr size_t kNumConstraints = 52;

        using Builder = typename CompositionPolynomialImpl<RescueAir>::Builder;
        using WordT = std::array<BaseFieldElement, kWordSize>;
        using WitnessT = std::vector<WordT>;

        struct State {
            using VectorT = RescueConstants::VectorT;
            explicit State(const VectorT &values) : values_(values) {
            }

            static State Uninitialized() {
                return State(UninitializedFieldElementArray<BaseFieldElement, kStateSize>());
            }

            BaseFieldElement &operator[](size_t i) {
                return values_.at(i);
            }
            const BaseFieldElement &operator[](size_t i) const {
                return values_.at(i);
            }

            ALWAYS_INLINE State operator*(const State &other) const {
                return State {VectorT {
                    values_[0] * other.values_[0], values_[1] * other.values_[1], values_[2] * other.values_[2],
                    values_[3] * other.values_[3], values_[4] * other.values_[4], values_[5] * other.values_[5],
                    values_[6] * other.values_[6], values_[7] * other.values_[7], values_[8] * other.values_[8],
                    values_[9] * other.values_[9], values_[10] * other.values_[10], values_[11] * other.values_[11]}};
            }

            VectorT &AsArray() {
                return values_;
            }

            /*
              Returns the third roots of all field elements within a state.
              Follows an optimized calculation of Pow() with exp=kCubeInverseExponent.
            */
            State BatchedThirdRoot() const;

        private:
            VectorT values_;
        };

        /*
          The public input for the AIR consists of:
          output - the result of the last hash, a tuple of 4 elements (p).
          chain_length - the number of hash invocations in the chain (n).
        */
        RescueAir(const WordT &output, uint64_t chain_length) :
            Air(Pow2(Log2Ceil(SafeDiv(chain_length, kHashesPerBatch) * kBatchHeight))), output_(output),
            chain_length_(chain_length) {
            ASSERT_RELEASE(TraceLength() >= SafeDiv(chain_length, kHashesPerBatch) * kBatchHeight,
                           "Data coset is too small.");
        }

        std::unique_ptr<CompositionPolynomial> CreateCompositionPolynomial(const BaseFieldElement &trace_generator,
                                                                           gsl::span<const ExtensionFieldElement>
                                                                               random_coefficients) const override;

        uint64_t GetCompositionPolynomialDegreeBound() const override {
            return 4 * TraceLength();
        }

        std::vector<std::pair<int64_t, uint64_t>> GetMask() const override;

        uint64_t NumRandomCoefficients() const override {
            return 2 * kNumConstraints;
        }

        uint64_t NumColumns() const override {
            return kNumColumns;
        }

        /*
          RescueAir does not use composition_neighbors in its ConstraintsEval implementation.
        */
        template<typename FieldElementT>
        ExtensionFieldElement ConstraintsEval(gsl::span<const FieldElementT> neighbors,
                                              gsl::span<const ExtensionFieldElement>
                                                  composition_neighbors,
                                              gsl::span<const FieldElementT>
                                                  periodic_columns,
                                              gsl::span<const ExtensionFieldElement>
                                                  random_coefficients,
                                              gsl::span<const FieldElementT>
                                                  point_powers,
                                              gsl::span<const BaseFieldElement>
                                                  shifts) const;

        /*
          Adds periodic columns to the composition polynomial.
        */
        void BuildPeriodicColumns(Builder *builder) const;

        /*
          Generates the trace.
          witness is the sequence of 4-tuples {w_i} such that H(...H(H(w_0, w_1), w_2) ..., w_n) = p.
        */
        Trace GetTrace(const WitnessT &witness) const;

        /*
          Receives a private input/witness, which is a vector of inputs to the hash chain:
              {w_0,w_1,w_2,...,w_n}
          Returns the public input, which is the output of the hash chain:
              H(...H(H(w_0, w_1), w_2) ..., w_n).
        */
        static WordT PublicInputFromPrivateInput(const WitnessT &witness);

    private:
        const WordT output_;
        const uint64_t chain_length_;
    };

    template<typename FieldElementT>
    ExtensionFieldElement RescueAir::ConstraintsEval(gsl::span<const FieldElementT> neighbors,
                                                     gsl::span<const ExtensionFieldElement> /*composition_neighbors*/,
                                                     gsl::span<const FieldElementT>
                                                         periodic_columns,
                                                     gsl::span<const ExtensionFieldElement>
                                                         random_coefficients,
                                                     gsl::span<const FieldElementT>
                                                         point_powers,
                                                     gsl::span<const BaseFieldElement>
                                                         shifts) const {
        using VectorT = std::array<FieldElementT, kStateSize>;
        ASSERT_RELEASE(neighbors.size() == 2 * kStateSize, "Wrong number of neighbors.");
        ASSERT_RELEASE(periodic_columns.size() == kNumPeriodicColumns, "Wrong number of periodic column elements.");
        ASSERT_RELEASE(random_coefficients.size() == NumRandomCoefficients(), "Wrong number of random coefficients.");
        ASSERT_RELEASE(point_powers.size() == 10, "point_powers should contain 10 elements.");
        ASSERT_RELEASE(shifts.size() == 6, "shifts should contain 6 elements.");

        const FieldElementT &point = point_powers[0];

        // domain0 = point^(trace_length / 32) - 1
        // i-th rows for i % 32 == 0, first row of each batch of 3 hashes.
        const FieldElementT &domain0 = point_powers[1] - BaseFieldElement::One();
        // domain1 = point^trace_length - 1 (all rows).
        const FieldElementT &domain1 = point_powers[2] - BaseFieldElement::One();
        // domain2 =
        // (point^(trace_length / 32) - 1) *
        // (point^(trace_length / 32) - gen^(30 * trace_length / 32)) *
        // (point^(trace_length / 32) - gen^(31 * trace_length / 32)).
        // i-th rows for i % 32 == 0,30,31. First, second to last and last rows of each batch of 3 hashes.
        const FieldElementT &domain2 = ((point_powers[1] - BaseFieldElement::One()) * (point_powers[1] - shifts[0])) *
                                       (point_powers[1] - shifts[1]);
        // domain3 =
        // (point^(trace_length / 32) - 1) *
        // (point^(trace_length / 32) - gen^(10 * trace_length / 32)) *
        // (point^(trace_length / 32) - gen^(20 * trace_length / 32)).
        // (point^(trace_length / 32) - gen^(30 * trace_length / 32)) *
        // (point^(trace_length / 32) - gen^(31 * trace_length / 32)) *
        // i-th rows for i % 32 == 0,10,20,30,31
        // First and last rows of each batch and first row of each hash.
        const FieldElementT &domain3 = ((((point_powers[1] - BaseFieldElement::One()) * (point_powers[1] - shifts[0])) *
                                         (point_powers[1] - shifts[1])) *
                                        (point_powers[1] - shifts[2])) *
                                       (point_powers[1] - shifts[3]);
        // domain4 =
        // (point^(trace_length / 32) - gen^(10 * trace_length / 32)) *
        // (point^(trace_length / 32) - gen^(20 * trace_length / 32)).
        // i-th rows for i % 32 == 10,20. First row of the second and third hashes in each batch.
        const FieldElementT &domain4 = (point_powers[1] - shifts[2]) * (point_powers[1] - shifts[3]);
        // domain5 = point^(trace_length / 32) - gen^(30 * trace_length / 32).
        // i-th rows for i % 32 == 30. Last row of the third hash in each batch of 3 hashes.
        const FieldElementT &domain5 = point_powers[1] - shifts[0];
        // domain6 = point^(trace_length / 32) - gen^(31 * trace_length / 32)
        // i-th rows for i % 32 == 31. Last row of each batch of 3 hashes.
        const FieldElementT &domain6 = point_powers[1] - shifts[1];
        // domain7 = point - gen^(trace_length - 1). Last row.
        const FieldElementT &domain7 = point - shifts[4];
        // domain8 = point - gen^(32 * (chain_length / 3 - 1) + 31). Output row.
        const FieldElementT &domain8 = point - shifts[5];

        // Compute inverses for the relevant domains.
        const FieldElementT &mult = domain0 * domain1 * domain4 * domain5 * domain6 * domain8;
        const FieldElementT &inv_mult = mult.Inverse();
        const FieldElementT &domain0_inv = inv_mult * (domain1 * (domain4 * (domain5 * (domain6 * domain8))));
        const FieldElementT &domain1_inv = domain0 * inv_mult * (domain4 * (domain5 * (domain6 * domain8)));
        const FieldElementT &domain4_inv = (domain0 * domain1) * inv_mult * (domain5 * (domain6 * domain8));
        const FieldElementT &domain5_inv = ((domain0 * domain1) * domain4) * inv_mult * (domain6 * domain8);
        const FieldElementT &domain6_inv = (((domain0 * domain1) * domain4) * domain5) * inv_mult * domain8;
        const FieldElementT &domain8_inv = ((((domain0 * domain1) * domain4) * domain5) * domain6) * inv_mult;

        // Compute the third powers of the state.
        VectorT x_cube = UninitializedFieldElementArray<FieldElementT, kStateSize>();
        for (size_t i = 0; i < kStateSize; ++i) {
            FieldElementT tmp = neighbors[i];
            x_cube[i] = tmp * tmp * tmp;
        }

        // Compute the state at the end of a full round.
        VectorT state_after_lin_perm = UninitializedFieldElementArray<FieldElementT, kStateSize>();
        for (size_t i = 0; i < kStateSize; ++i) {
            FieldElementT tmp = periodic_columns[i];
            for (size_t j = 0; j < kStateSize; ++j) {
                tmp += (kRescueConstants.k_mds_matrix[i][j] * x_cube[j]);
            }
            state_after_lin_perm[i] = tmp;
        }

        // Compute the state at the beginning of the next full round.
        VectorT state_before_next_lin_perm_cubed = UninitializedFieldElementArray<FieldElementT, kStateSize>();
        for (size_t i = 0; i < kStateSize; ++i) {
            FieldElementT tmp = FieldElementT::Zero();
            for (size_t j = 0; j < kStateSize; ++j) {
                tmp += kRescueConstants.k_mds_matrix_inverse[i][j] *
                       (neighbors[kStateSize + j] - periodic_columns[kStateSize + j]);
            }
            state_before_next_lin_perm_cubed[i] = tmp * tmp * tmp;
        }

        uint8_t rand_coef_index = 0;
        ExtensionFieldElement res = ExtensionFieldElement::Zero();
        {
            // Compute a sum of constraints for rows i % 32 == 0 (first row of each batch of 3 hashes).
            ExtensionFieldElement sum = ExtensionFieldElement::Zero();

            // Add a constraint that forces the capacity part of the first hash to be zero.
            for (size_t i = 0; i < kWordSize; ++i, rand_coef_index += 2) {
                const FieldElementT constraint = neighbors[2 * kWordSize + i];
                // point_powers[3] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 0,
                // trace_length / 32).
                const ExtensionFieldElement deg_adj_rand_coef =
                    random_coefficients[rand_coef_index] + random_coefficients[rand_coef_index + 1] * point_powers[3];
                sum += constraint * deg_adj_rand_coef;
            }

            // Add a constraint that computes the first half round of the first hash and places the result
            // at the second row.
            for (size_t i = 0; i < kStateSize; ++i, rand_coef_index += 2) {
                const FieldElementT constraint =
                    neighbors[i] + periodic_columns[i] - state_before_next_lin_perm_cubed[i];
                // point_powers[4] = point^degreeAdjustment(composition_degree_bound, 3 * (trace_length - 1),
                // 0, trace_length / 32).
                const ExtensionFieldElement deg_adj_rand_coef =
                    random_coefficients[rand_coef_index] + random_coefficients[rand_coef_index + 1] * point_powers[4];
                sum += constraint * deg_adj_rand_coef;
            }
            res += sum * domain0_inv;
        }

        // Constraints that check the consistency between states:
        //
        // Note that the constraints between states inside a hash and between hashes in the same batch are
        // not identical, but are very similar for the first 4 state elements.
        //
        // In the connection between hashes, the capacity is nullified and the second input is reset to
        // some nondeterministic witness.
        //
        // State at the end of the first hash (which corresponds to state_after_lin_perm):
        //    OUTPUT0 | JUNK | JUNK
        //
        // State at the beginning of the second hash (which corresponds to
        // state_before_next_lin_perm_cubed - k_0, where k_0 is the independent round constant that is
        // added before the first round):
        //    INP0 | INP1 | CAPACITY=0
        //
        // To check the consistency between those states, one needs to check that:
        // * OUTPUT0 == INP0
        // * CAPACITY == 0
        //
        // Checking the first item corresponds to checking:
        //   state_after_lin_perm == state_before_next_lin_perm_cubed - k_0.
        // This equation is very similar to the constraints between states inside a hash, which is:
        //   state_after_lin_perm == state_before_next_lin_perm_cubed.
        // In order to reuse the same constraints, we add k_0 to even_round_constants[10] and
        // even_round_constants[20], and thus +k_0 is already part of state_after_lin_perm.
        {
            ExtensionFieldElement sum = ExtensionFieldElement::Zero();
            {
                // Compute a sum of constraints for all rows except i % 32 == 0,30,31 (first, penultimate
                // and last rows of each batch of 3 hashes).
                ExtensionFieldElement inner_sum = ExtensionFieldElement::Zero();

                // Add a constraint that connects the middle of a round (current row) with the middle of the
                // next round (next row) for state[0], ..., state[3].
                for (size_t i = 0; i < kWordSize; ++i, rand_coef_index += 2) {
                    const FieldElementT constraint = state_after_lin_perm[i] - state_before_next_lin_perm_cubed[i];
                    // point_powers[5] = point^degreeAdjustment(composition_degree_bound, 3 * (trace_length -
                    // 1), trace_length / 32 + trace_length / 32 + trace_length / 32, trace_length).
                    const ExtensionFieldElement deg_adj_rand_coef =
                        random_coefficients[rand_coef_index] +
                        random_coefficients[rand_coef_index + 1] * point_powers[5];
                    inner_sum += constraint * deg_adj_rand_coef;
                }
                sum += inner_sum * domain2;
            }

            {
                // Compute a sum of constraints for all rows except i % 32 == 0,10,20,30,31 (first and last
                // rows of each batch and first row of each hash).
                ExtensionFieldElement inner_sum = ExtensionFieldElement::Zero();

                // Add a constraint that connects the middle of a round (current row) with the middle of the
                // next round (next row) for state[4], ..., state[11].
                for (size_t i = kWordSize; i < kStateSize; ++i, rand_coef_index += 2) {
                    const FieldElementT constraint = state_after_lin_perm[i] - state_before_next_lin_perm_cubed[i];
                    // point_powers[6] = point^degreeAdjustment(composition_degree_bound, 3 * (trace_length -
                    // 1), trace_length / 32 + trace_length / 32 + trace_length / 32 + trace_length / 32 +
                    // trace_length / 32, trace_length).
                    const ExtensionFieldElement deg_adj_rand_coef =
                        random_coefficients[rand_coef_index] +
                        random_coefficients[rand_coef_index + 1] * point_powers[6];
                    inner_sum += constraint * deg_adj_rand_coef;
                }
                sum += inner_sum * domain3;
            }
            res += sum * domain1_inv;
        }

        {
            // Compute a sum of constraints for rows i % 32 == 10,20 (first row of the second and third
            // hashes in each batch).
            ExtensionFieldElement sum = ExtensionFieldElement::Zero();

            // Add a constraint that forces the capacity part of the second and third hashes to be zero.
            // As mentioned in the previos constraint:
            // State before second hash (corresponds to state_before_next_lin_perm_cubed - k_0):
            //   INP0 | INP1 | 0
            // And we require 0 in the capacity range.
            for (size_t i = kStateSize - kWordSize; i < kStateSize; ++i, rand_coef_index += 2) {
                const FieldElementT constraint = periodic_columns[i] - state_before_next_lin_perm_cubed[i];
                // point_powers[7] = point^degreeAdjustment(composition_degree_bound, 3 * (trace_length - 1),
                // 0, trace_length / 32 + trace_length / 32).
                const ExtensionFieldElement deg_adj_rand_coef =
                    random_coefficients[rand_coef_index] + random_coefficients[rand_coef_index + 1] * point_powers[7];
                sum += constraint * deg_adj_rand_coef;
            }
            res += sum * domain4_inv;
        }

        {
            // Compute a sum of constraints for rows i % 32 == 30 (last row of the third hash in each batch
            // of 3 hashes).
            ExtensionFieldElement sum = ExtensionFieldElement::Zero();

            // Add a constraint that does the final half round of the third hash.
            for (size_t i = 0; i < kStateSize; ++i, rand_coef_index += 2) {
                const FieldElementT constraint = state_after_lin_perm[i] - neighbors[kStateSize + i];
                // point_powers[4] = point^degreeAdjustment(composition_degree_bound, 3 * (trace_length - 1),
                // 0, trace_length / 32).
                const ExtensionFieldElement deg_adj_rand_coef =
                    random_coefficients[rand_coef_index] + random_coefficients[rand_coef_index + 1] * point_powers[4];
                sum += constraint * deg_adj_rand_coef;
            }
            res += sum * domain5_inv;
        }

        {
            // Compute a sum of constraints for rows i % 32 == 31, i < trace length-1 (last
            // row of each batch of 3 hashes except the last row of the trace).
            ExtensionFieldElement sum = ExtensionFieldElement::Zero();

            // Add a constraint that moves the output of the third hash of a batch to the input of the
            // first hash of the next batch.
            for (size_t i = 0; i < kWordSize; ++i, rand_coef_index += 2) {
                const FieldElementT constraint = neighbors[i] - neighbors[kStateSize + i];
                // point_powers[8] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 1,
                // trace_length / 32).
                const ExtensionFieldElement deg_adj_rand_coef =
                    random_coefficients[rand_coef_index] + random_coefficients[rand_coef_index + 1] * point_powers[8];
                sum += constraint * deg_adj_rand_coef;
            }
            sum *= domain7;

            res += sum * domain6_inv;
        }

        {
            // Compute a sum of constraints for the output row.
            ExtensionFieldElement sum = ExtensionFieldElement::Zero();

            // Add a constraint that determines the output after chain_length invocations of the hash.
            for (size_t i = 0; i < kWordSize; ++i, rand_coef_index += 2) {
                const FieldElementT constraint = neighbors[i] - (output_[i]);
                // point_powers[9] = point^degreeAdjustment(composition_degree_bound, trace_length - 1, 0, 1).
                const ExtensionFieldElement deg_adj_rand_coef =
                    random_coefficients[rand_coef_index] + random_coefficients[rand_coef_index + 1] * point_powers[9];
                sum += constraint * deg_adj_rand_coef;
            }
            res += sum * domain8_inv;
        }
        return res;
    }

    namespace {

        using State = RescueAir::State;

        /*
          Appends state as a whole row to the trace.
        */
        void PushState(gsl::span<std::vector<BaseFieldElement>> trace_values, const State &state) {
            for (size_t i = 0; i < RescueAir::kNumColumns; ++i) {
                trace_values[i].push_back(state[i]);
            }
        }

        State ApplyFirstSBox(const State &state) {
            return state.BatchedThirdRoot();
        }
        State ApplySecondSBox(const State &state) {
            return state * state * state;
        }

        /*
          Applies half a round to the state.
          round_index - a number in the range 0 to 9, indicates which round to apply.
          is_first_half - if true, applies the first half round, else applies the second half round.
        */
        void HalfRound(State *state, size_t round_index, bool is_first_half) {
            State state_after_sbox = is_first_half ? ApplyFirstSBox(*state) : ApplySecondSBox(*state);
            LinearTransformation(kRescueConstants.k_mds_matrix, state_after_sbox.AsArray(), &state->AsArray());

            const size_t round_constants_index = 2 * round_index + (is_first_half ? 1 : 2);
            for (size_t i = 0; i < RescueAir::kStateSize; ++i) {
                (*state)[i] += kRescueConstants.k_round_constants.at(round_constants_index).at(i);
            }
        }

    }    // namespace

    std::unique_ptr<CompositionPolynomial>
        RescueAir::CreateCompositionPolynomial(const BaseFieldElement &trace_generator,
                                               gsl::span<const ExtensionFieldElement>
                                                   random_coefficients) const {
        Builder builder(kNumPeriodicColumns);
        const uint64_t composition_degree_bound = GetCompositionPolynomialDegreeBound();

        // Number of batches, where each batch corresponds to 32 trace lines and 3 hash invocations.
        const uint64_t n_batches = SafeDiv(trace_length_, kBatchHeight);
        // Prepare a list of all the values used in expressions of the form 'point^value', where point
        // represents the field elements that will be substituted in the composition polynomial.
        const std::vector<uint64_t> point_exponents = {
            n_batches,
            trace_length_,
            composition_degree_bound - trace_length_ + n_batches,
            composition_degree_bound + 2 - (3 * trace_length_) + n_batches,
            composition_degree_bound + 2 * (1 - trace_length_) - (3 * n_batches),
            composition_degree_bound + 2 * (1 - trace_length_) - (5 * n_batches),
            composition_degree_bound + 2 - (3 * trace_length_) + (2 * n_batches),
            composition_degree_bound - 1 - trace_length_ + n_batches,
            composition_degree_bound - trace_length_ + 1,
        };

        const std::vector<uint64_t> gen_exponents = {
            SafeDiv(15 * (trace_length_), 16),
            SafeDiv(31 * (trace_length_), 32),
            SafeDiv(5 * (trace_length_), 16),
            SafeDiv(5 * (trace_length_), 8),
            trace_length_ - 1,
            (32 * (SafeDiv(chain_length_, 3) - 1)) + 31,
        };

        BuildPeriodicColumns(&builder);

        return builder.BuildUniquePtr(UseOwned(this), trace_generator, trace_length_, random_coefficients,
                                      point_exponents, BatchPow(trace_generator, gen_exponents));
    }

    std::vector<std::pair<int64_t, uint64_t>> RescueAir::GetMask() const {
        std::vector<std::pair<int64_t, uint64_t>> mask;
        mask.reserve(2 * kStateSize);
        for (uint64_t row_offset = 0; row_offset < 2; ++row_offset) {
            for (size_t i = 0; i < kStateSize; ++i) {
                mask.emplace_back(row_offset, i);
            }
        }
        return mask;
    }

    void RescueAir::BuildPeriodicColumns(Builder *builder) const {
        // Prepare the round constants with kHashesPerBatch copies each, in the order they are used.
        // There are kNumRounds pairs of constant kStateSize-vectors that are used in each of the
        // kNumRounds rounds of Rescue. The kNumRounds-vector of kStateSize-vectors created by the first
        // element of all the pairs is named even_round_constants, and the kNumRounds-vector of
        // kStateSize-vectors created by the second element of all the pairs is named odd_round_constants.
        // Since there are kHashesPerBatch hash instances in one batch, these constants need to be
        // copied kHashesPerBatch times, once for each hash instance.
        // For more information, see the function ConstraintsEval in the file rescue_air.inl, specifically
        // the comment regarding "constraints that check the consistency between states".

        for (size_t i = 0; i < kStateSize; ++i) {
            std::vector<BaseFieldElement> even_round_constants;
            std::vector<BaseFieldElement> odd_round_constants;
            even_round_constants.reserve(kBatchHeight);
            odd_round_constants.reserve(kBatchHeight);
            // The first element is initialized to zero because of the use of operator+= later on.
            even_round_constants.push_back(BaseFieldElement::Zero());

            for (size_t j = 0; j < kHashesPerBatch; ++j) {
                if (i < kWordSize) {
                    even_round_constants.back() += kRescueConstants.k_round_constants[0][i];
                } else {
                    even_round_constants.back() = kRescueConstants.k_round_constants[0][i];
                }
                for (size_t round = 0; round < kNumRounds; ++round) {
                    odd_round_constants.emplace_back(kRescueConstants.k_round_constants.at(2 * round + 1).at(i));
                    even_round_constants.emplace_back(kRescueConstants.k_round_constants.at(2 * round + 2).at(i));
                }
            }

            // Pad the vectors with zeros to make them of size kBatchHeight.
            even_round_constants.push_back(BaseFieldElement::Zero());
            odd_round_constants.push_back(BaseFieldElement::Zero());
            odd_round_constants.push_back(BaseFieldElement::Zero());
            ASSERT_RELEASE(even_round_constants.size() == kBatchHeight, "Wrong length for periodic column.");
            ASSERT_RELEASE(odd_round_constants.size() == kBatchHeight, "Wrong length for periodic column.");
            builder->AddPeriodicColumn(PeriodicColumn(even_round_constants, trace_length_), i);
            builder->AddPeriodicColumn(PeriodicColumn(odd_round_constants, trace_length_), kStateSize + i);
        }
    }

    Trace RescueAir::GetTrace(const WitnessT &witness) const {
        ASSERT_RELEASE(witness.size() == chain_length_ + 1, "Witness size is " + std::to_string(witness.size()) +
                                                                ", should be " + std::to_string(chain_length_ + 1) +
                                                                ".");
        static_assert(kNumColumns == kStateSize, "Wrong number of columns.");

        std::vector<std::vector<BaseFieldElement>> trace_values(kNumColumns);
        for (auto &column : trace_values) {
            column.reserve(trace_length_);
        }

        State state = State::Uninitialized();
        // First witness is the left input for the first hash.
        state[0] = witness[0][0];
        state[1] = witness[0][1];
        state[2] = witness[0][2];
        state[3] = witness[0][3];

        bool output_checked = false;
        for (size_t hash_index = 1; hash_index <= kHashesPerBatch * SafeDiv(trace_length_, kBatchHeight);) {
            for (size_t hash_index_in_batch = 0; hash_index_in_batch < kHashesPerBatch;
                 ++hash_index_in_batch, ++hash_index) {
                state[4] = hash_index < witness.size() ? witness[hash_index][0] : BaseFieldElement::Zero();
                state[5] = hash_index < witness.size() ? witness[hash_index][1] : BaseFieldElement::Zero();
                state[6] = hash_index < witness.size() ? witness[hash_index][2] : BaseFieldElement::Zero();
                state[7] = hash_index < witness.size() ? witness[hash_index][3] : BaseFieldElement::Zero();
                state[8] = BaseFieldElement::Zero();
                state[9] = BaseFieldElement::Zero();
                state[10] = BaseFieldElement::Zero();
                state[11] = BaseFieldElement::Zero();

                if (hash_index_in_batch == 0) {
                    // Row 0 is the original state.
                    PushState(trace_values, state);
                }

                for (size_t k = 0; k < kStateSize; ++k) {
                    state[k] += kRescueConstants.k_round_constants[0][k];
                }

                for (size_t round = 0; round < RescueConstants::kNumRounds; ++round) {
                    HalfRound(&state, round, true);
                    // We only store the state, midway through the round.
                    PushState(trace_values, state);
                    HalfRound(&state, round, false);
                }
            }
            // Row 31 is the resulting state of the third hash.
            ASSERT_RELEASE(trace_values[0].size() % 32 == 31, "The current row number is not correct.");
            PushState(trace_values, state);

            if (hash_index == witness.size()) {
                // Assert that the output equals the expected output.
                for (size_t k = 0; k < kWordSize; ++k) {
                    ASSERT_RELEASE(state[k] == output_[k], "Given witness is not a correct preimage.");
                }
                output_checked = true;
            }
        }

        ASSERT_RELEASE(trace_values[0].size() == trace_length_, "Wrong trace length.");
        ASSERT_RELEASE(output_checked, "Output correctness was not checked.");
        return Trace(std::move(trace_values));
    }

    auto RescueAir::PublicInputFromPrivateInput(const WitnessT &witness) -> WordT {
        ASSERT_RELEASE((witness.size() - 1) % kHashesPerBatch == 0,
                       "Incompatible witness size. The number of hash invocations needs to be divisible "
                       "by" +
                           std::to_string(kHashesPerBatch) + ".");

        State state = State::Uninitialized();
        // First witness is the left input for the first hash.
        state[0] = witness[0][0];
        state[1] = witness[0][1];
        state[2] = witness[0][2];
        state[3] = witness[0][3];

        for (auto witness_iter = witness.begin() + 1; witness_iter != witness.end(); ++witness_iter) {
            state[4] = (*witness_iter)[0];
            state[5] = (*witness_iter)[1];
            state[6] = (*witness_iter)[2];
            state[7] = (*witness_iter)[3];
            state[8] = BaseFieldElement::Zero();
            state[9] = BaseFieldElement::Zero();
            state[10] = BaseFieldElement::Zero();
            state[11] = BaseFieldElement::Zero();

            for (size_t i = 0; i < kStateSize; ++i) {
                state[i] += kRescueConstants.k_round_constants[0][i];
            }

            for (size_t round = 0; round < RescueConstants::kNumRounds; ++round) {
                HalfRound(&state, round, true);
                HalfRound(&state, round, false);
            }
        }

        return {state[0], state[1], state[2], state[3]};
    }

    RescueAir::State RescueAir::State::BatchedThirdRoot() const {
        // Efficiently computes the third root (i.e. base ^ kCubeInverseExponent, where
        // kCubeInverseExponent = 0b1010101010101010101010110001010101010101010101010101010101011) by
        // using 68 multiplications.

        const State &base = *this;

        // Computes base ^ 0b10.
        const State temp01 = base * base;
        // Computes base ^ 0b100.
        const State temp02 = temp01 * temp01;
        // Computes base ^ 0b1000.
        const State temp03 = temp02 * temp02;

        // Computes base ^ 0b1010.
        const State temp04 = temp03 * temp01;

        // Computes base ^ 0b10100.
        const State temp05 = temp04 * temp04;
        // Computes base ^ 0b101000.
        const State temp06 = temp05 * temp05;
        // Computes base ^ 0b1010000.
        const State temp07 = temp06 * temp06;
        // Computes base ^ 0b10100000.
        const State temp08 = temp07 * temp07;

        // Computes base ^ 0b10101010.
        const State temp09 = temp08 * temp04;

        // Computes base ^ 0b1010101000000000.
        State prev = temp09;
        for (size_t i = 9; i < 17; ++i) {
            prev = prev * prev;
        }
        const State temp17 = prev;

        // Computes base ^ 0b1010101010101010.
        const State temp18 = temp17 * temp09;

        // Computes base ^ 0b101010101010101000000000.
        prev = temp18;
        for (size_t i = 18; i < 26; ++i) {
            prev = prev * prev;
        }
        const State temp26 = prev;

        // Computes base ^ 0b101010101010101010101010.
        const State temp27 = temp26 * temp09;
        // Computes base ^ 0b101010101010101010101011.
        const State temp28 = temp27 * base;

        // Computes base ^ 0b10101010101010101010101100000000000.
        prev = temp28;
        for (size_t i = 28; i < 39; ++i) {
            prev = prev * prev;
        }
        const State temp39 = prev;

        // Computes base ^ 0b10101010101010101010101100010101010.
        const State temp40 = temp39 * temp09;
        // Computes base ^ 0b101010101010101010101011000101010100.
        const State temp41 = temp40 * temp40;
        // Computes base ^ 0b1010101010101010101010110001010101000.
        const State temp42 = temp41 * temp41;
        // Computes base ^ 0b1010101010101010101010110001010101010.
        const State temp43 = temp42 * temp01;

        // Computes base ^ 0b1010101010101010101010110001010101010000000000000000000000000.
        prev = temp43;
        for (size_t i = 43; i < 67; ++i) {
            prev = prev * prev;
        }
        const State temp67 = prev;

        // Returns base ^ 0b1010101010101010101010110001010101010101010101010101010101011.
        return temp67 * temp28;
    }

}    // namespace starkware

#endif    // STARKWARE_AIR_RESCUE_RESCUE_AIR_H_
