#ifndef STARKWARE_STARK_COMMITTED_TRACE_H_
#define STARKWARE_STARK_COMMITTED_TRACE_H_

#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#include "third_party/gsl/gsl-lite.hpp"

#include "starkware/air/trace.h"
#include "starkware/algebra/domains/coset.h"
#include "starkware/algebra/domains/evaluation_domain.h"
#include "starkware/algebra/lde/cached_lde_manager.h"
#include "starkware/commitment_scheme/table_prover.h"
#include "starkware/commitment_scheme/table_verifier.h"

namespace starkware {

    /*
      Given a trace (a vector of column evaluations over the trace domain), this class is responsible
      for computing the trace LDE over the evaluation domain, and for the commitment and decommitment of
      that LDE.
    */
    template<typename FieldElementT>
    class CommittedTraceProverBase {
    public:
        virtual ~CommittedTraceProverBase() = default;

        /*
          Returns the number of columns.
        */
        virtual size_t NumColumns() const = 0;

        /*
          Returns the LDE manager.
        */
        virtual CachedLdeManager<FieldElementT> *GetLde() = 0;

        /*
          Computes the trace LDE over the evaluation domain and then commits to the LDE evaluations.

          If eval_in_natural_order is true/false, then each trace column consists of evaluations over a
          natural/bit-reversed order enumeration of the trace_domain, respectively. (see
          multiplicative_group_ordering.h)

          Commitments are expected to be over bit-reversed order evaluations.
          If eval_in_natural_order is true, then the LDE evaluations are bit-reversed prior to commitment.
        */
        virtual void Commit(TraceBase<FieldElementT> &&trace, const Coset &trace_domain,
                            bool eval_in_natural_order) = 0;

        /*
          Given queries for the commitment, computes the relevant commitment leaves from the LDE, and
          decommits them. queries is a list of tuples of the form (coset_index, offset, column_index).
        */
        virtual void DecommitQueries(gsl::span<const std::tuple<uint64_t, uint64_t, size_t>> queries) const = 0;

        /*
          Computes the mask of the trace columns at a point.
          Its purpose is for out of domain sampling.
          Note that point is of type ExtensionFieldElement regardless of FieldElementT since this function
          is used for out of domain sampling.
        */
        virtual void EvalMaskAtPoint(gsl::span<const std::pair<int64_t, uint64_t>> mask,
                                     const ExtensionFieldElement &point,
                                     gsl::span<ExtensionFieldElement> output) const = 0;

        /*
          Calls the LDE manager FinalizeEvaluations function. Once called, no new uncached evaluations
          such as GetLde()->EvalAtPointsNotCached(), will occur anymore.
        */
        virtual void FinalizeEval() = 0;
    };

    template<typename FieldElementT>
    class CommittedTraceProver : public CommittedTraceProverBase<FieldElementT> {
    public:
        /*
          Commitment is done over the evaluation_domain, where each commitment row is of size n_columns.
          Since commitment is expected to be over bit-reversed order evaluations, coset order is
          bit-reversed in CommittedTraceProver (this happens in Commit(), during the creation of the LDE
          manager).

          table_prover_factory is a function that given the size of the data to commit on, creates a
          TableProver which is used for committing and decommitting the data.
        */
        CommittedTraceProver(MaybeOwnedPtr<const EvaluationDomain> evaluation_domain, size_t n_columns,
                             const TableProverFactory<FieldElementT> &table_prover_factory);

        size_t NumColumns() const override {
            return n_columns_;
        }

        CachedLdeManager<FieldElementT> *GetLde() override {
            return lde_.get();
        }

        void Commit(TraceBase<FieldElementT> &&trace, const Coset &trace_domain, bool eval_in_natural_order) override;

        void DecommitQueries(gsl::span<const std::tuple<uint64_t, uint64_t, size_t>> queries) const override;

        void EvalMaskAtPoint(gsl::span<const std::pair<int64_t, uint64_t>> mask, const ExtensionFieldElement &point,
                             gsl::span<ExtensionFieldElement> output) const override;

        void FinalizeEval() override {
            lde_->FinalizeEvaluations();
        }

    private:
        /*
          Given commitment row indices, computes the rows using lde_. output must be of size NumColumns(),
          and each span inside will be filled with the column evaluations at the given rows.
        */
        void AnswerQueries(const std::vector<uint64_t> &rows_to_fetch, gsl::span<const gsl::span<FieldElementT>> output)
            const;

        std::unique_ptr<CachedLdeManager<FieldElementT>> lde_;
        MaybeOwnedPtr<const EvaluationDomain> evaluation_domain_;
        size_t n_columns_;
        std::unique_ptr<TableProver<FieldElementT>> table_prover_;
    };

    /*
      The verifier equivalent of CommittedTraceProverBase.
    */
    template<typename FieldElementT>
    class CommittedTraceVerifierBase {
    public:
        virtual ~CommittedTraceVerifierBase() = default;

        virtual size_t NumColumns() const = 0;

        /*
          Reads the commitment.
        */
        virtual void ReadCommitment() = 0;

        /*
          Verifies that the answers to the given queries are indeed the ones committed to by the prover.
          Returns the queries results.
        */
        virtual std::vector<FieldElementT>
            VerifyDecommitment(gsl::span<const std::tuple<uint64_t, uint64_t, size_t>> queries) const = 0;
    };

    template<typename FieldElementT>
    class CommittedTraceVerifier : public CommittedTraceVerifierBase<FieldElementT> {
    public:
        /*
          Given the size of the committed data, table_verifier_factory is a function that creates a
          TableVerifier which is used for reading and verifying commitments.
        */
        CommittedTraceVerifier(MaybeOwnedPtr<const EvaluationDomain> evaluation_domain, size_t n_columns,
                               const TableVerifierFactory<FieldElementT> &table_verifier_factory);

        size_t NumColumns() const override {
            return n_columns_;
        }

        void ReadCommitment() override;

        std::vector<FieldElementT>
            VerifyDecommitment(gsl::span<const std::tuple<uint64_t, uint64_t, size_t>> queries) const override;

    private:
        MaybeOwnedPtr<const EvaluationDomain> evaluation_domain_;
        const size_t n_columns_;
        std::unique_ptr<TableVerifier<FieldElementT>> table_verifier_;
    };

    namespace committed_trace {
        namespace details {

            /*
              Creates a cached LDE manager with coset offsets in bit-reversed order.
            */
            template<typename FieldElementT>
            inline std::unique_ptr<CachedLdeManager<FieldElementT>>
                CreateLdeManager(const Coset &trace_domain, const EvaluationDomain &evaluation_domain,
                                 bool eval_in_natural_order) {
                // Create LDE manager.
                std::unique_ptr<LdeManager<FieldElementT>> lde_manager =
                    MakeLdeManager<FieldElementT>(trace_domain, eval_in_natural_order);

                // Bit-reverse coset offsets.
                const size_t n_cosets = evaluation_domain.NumCosets();
                std::vector<BaseFieldElement> coset_offsets;
                coset_offsets.reserve(n_cosets);
                const size_t log_cosets = SafeLog2(n_cosets);
                for (uint64_t i = 0; i < n_cosets; ++i) {
                    coset_offsets.emplace_back(evaluation_domain.CosetOffsets()[BitReverse(i, log_cosets)]);
                }

                // Create CachedLdeManager.
                return std::make_unique<CachedLdeManager<FieldElementT>>(TakeOwnershipFrom(std::move(lde_manager)),
                                                                         std::move(coset_offsets));
            }

        }    // namespace details
    }        // namespace committed_trace

    // ------------------------------------------------------------------------------------------
    //  Prover side
    // ------------------------------------------------------------------------------------------

    template<typename FieldElementT>
    CommittedTraceProver<FieldElementT>::CommittedTraceProver(
        MaybeOwnedPtr<const EvaluationDomain> evaluation_domain, size_t n_columns,
        const TableProverFactory<FieldElementT> &table_prover_factory) :
        evaluation_domain_(std::move(evaluation_domain)),
        n_columns_(n_columns), table_prover_(table_prover_factory(evaluation_domain_->NumCosets(),
                                                                  evaluation_domain_->TraceSize(), n_columns_)) {
    }

    template<typename FieldElementT>
    void CommittedTraceProver<FieldElementT>::Commit(TraceBase<FieldElementT> &&trace, const Coset &trace_domain,
                                                     bool eval_in_natural_order) {
        ASSERT_RELEASE(trace.Width() == n_columns_, "Wrong number of columns.");
        ASSERT_RELEASE(trace.Length() == evaluation_domain_->TraceSize(), "Wrong trace length.");

        // Create an LDE manager and add column evaluations.
        lde_ = committed_trace::details::CreateLdeManager<FieldElementT>(trace_domain, *evaluation_domain_,
                                                                         eval_in_natural_order);

        ProfilingBlock interpolation_block("Interpolation");
        auto columns = std::move(trace).ConsumeAsColumnsVector();
        for (auto &&column : columns) {
            lde_->AddEvaluation(std::move(column));
        }
        lde_->FinalizeAdding();
        interpolation_block.CloseBlock();

        // On each coset, evaluate the LDE and then add evaluation to the commitment scheme (bit-reverse
        // the evaluations if necessary).
        const size_t trace_length = evaluation_domain_->TraceSize();
        TaskManager::GetInstance().ParallelFor(
            evaluation_domain_->NumCosets(), [this, eval_in_natural_order, trace_length](const TaskInfo &task_info) {
                const size_t coset_index = task_info.start_idx;

                // Allocate storage for bit-reversing the evaluations.
                std::vector<std::vector<FieldElementT>> bitrev_evaluations;
                bitrev_evaluations.reserve(n_columns_);

                // Evaluate the LDE on the coset.
                ProfilingBlock lde_block("LDE");
                const auto lde_evaluations = lde_->EvalOnCoset(coset_index);
                std::vector<gsl::span<const FieldElementT>> lde_evaluations_spans;
                lde_evaluations_spans.reserve(lde_evaluations->size());
                for (const auto &lde_evaluation : *lde_evaluations) {
                    lde_evaluations_spans.push_back(lde_evaluation);
                }
                lde_block.CloseBlock();

                // Bit-reverse if necessary.
                if (eval_in_natural_order) {
                    ProfilingBlock bit_reversal_block("BitReversal of columns");
                    for (const auto &lde_evaluation : *lde_evaluations) {
                        bitrev_evaluations.emplace_back(FieldElementT::UninitializedVector(trace_length));
                        BitReverseVector(gsl::make_span(lde_evaluation), gsl::make_span(bitrev_evaluations.back()));
                    }
                    bit_reversal_block.CloseBlock();
                }

                // Add the LDE coset evaluation to the commitment scheme.
                ProfilingBlock commit_to_lde_block("Commit to LDE");
                if (eval_in_natural_order) {
                    table_prover_->AddSegmentForCommitment({bitrev_evaluations.begin(), bitrev_evaluations.end()},
                                                           coset_index);
                } else {
                    table_prover_->AddSegmentForCommitment(lde_evaluations_spans, coset_index);
                }
                commit_to_lde_block.CloseBlock();
            });

        // Commit to the LDE evaluations.
        table_prover_->Commit();
    }

    template<typename FieldElementT>
    void CommittedTraceProver<FieldElementT>::DecommitQueries(
        gsl::span<const std::tuple<uint64_t, uint64_t, size_t>> queries) const {
        const uint64_t trace_length = evaluation_domain_->TraceSize();

        // The commitment items we need to open.
        std::set<RowCol> data_queries;
        for (const auto &[coset_index, offset, column_index] : queries) {
            ASSERT_RELEASE(coset_index < evaluation_domain_->NumCosets(), "Coset index out of range.");
            ASSERT_RELEASE(offset < trace_length, "Coset offset out of range.");
            ASSERT_RELEASE(column_index < NumColumns(), "Column index out of range.");
            data_queries.emplace(coset_index * trace_length + offset, column_index);
        }

        // Commitment rows to fetch.
        const std::vector<uint64_t> rows_to_fetch =
            table_prover_->StartDecommitmentPhase(data_queries, /*integrity_queries=*/ {});

        // Prepare storage for the requested rows.
        std::vector<std::vector<FieldElementT>> elements_data;
        elements_data.reserve(NumColumns());
        for (size_t i = 0; i < NumColumns(); ++i) {
            elements_data.push_back(FieldElementT::UninitializedVector(rows_to_fetch.size()));
        }

        // Computes the rows.
        AnswerQueries(rows_to_fetch, std::vector<gsl::span<FieldElementT>>(elements_data.begin(), elements_data.end()));

        // Decommit the rows.
        table_prover_->Decommit(
            std::vector<gsl::span<const FieldElementT>>(elements_data.begin(), elements_data.end()));
    }

    template<typename FieldElementT>
    void CommittedTraceProver<FieldElementT>::EvalMaskAtPoint(gsl::span<const std::pair<int64_t, uint64_t>> mask,
                                                              const ExtensionFieldElement &point,
                                                              gsl::span<ExtensionFieldElement> output) const {
        ASSERT_RELEASE(mask.size() == output.size(), "Mask size does not equal output size.");

        const BaseFieldElement &trace_gen = evaluation_domain_->TraceGenerator();

        // A map from column index to pairs (mask_row_offset, mask_index).
        std::map<uint64_t, std::vector<std::pair<int64_t, size_t>>> columns;
        for (size_t mask_index = 0; mask_index < mask.size(); ++mask_index) {
            const auto &[row_offset, column_index] = mask[mask_index];
            ASSERT_RELEASE(row_offset >= 0, "Negative mask row offsets are not supported.");
            columns[column_index].emplace_back(row_offset, mask_index);
        }

        // Evaluate mask at each column.
        for (const auto &[column_index, column_offsets] : columns) {
            // Compute points to evaluate at.
            std::vector<ExtensionFieldElement> points;
            points.reserve(column_offsets.size());
            for (const auto &offset_pair : column_offsets) {
                const int64_t row_offset = offset_pair.first;
                points.push_back(point * Pow(trace_gen, row_offset));
            }

            // Allocate output.
            auto column_output = ExtensionFieldElement::UninitializedVector(column_offsets.size());

            // Evaluate.
            lde_->EvalAtPointsNotCached(column_index, points, column_output);

            // Place outputs at the correct place.
            for (size_t i = 0; i < column_offsets.size(); ++i) {
                const size_t mask_index = column_offsets[i].second;
                output[mask_index] = column_output.at(i);
            }
        }
    }

    template<typename FieldElementT>
    void CommittedTraceProver<FieldElementT>::AnswerQueries(const std::vector<uint64_t> &rows_to_fetch,
                                                            gsl::span<const gsl::span<FieldElementT>>
                                                                output) const {
        const uint64_t trace_length = evaluation_domain_->TraceSize();

        // Translate queries to coset and point indices.
        std::vector<std::pair<uint64_t, uint64_t>> coset_and_point_indices;
        coset_and_point_indices.reserve(rows_to_fetch.size());
        for (const uint64_t row : rows_to_fetch) {
            const uint64_t coset_index = row / trace_length;
            const uint64_t offset = row % trace_length;
            coset_and_point_indices.emplace_back(coset_index, offset);
        }

        // Call CachedLdeManager::EvalAtPoints().
        lde_->EvalAtPoints(coset_and_point_indices, output);
    }

    // ------------------------------------------------------------------------------------------
    //  Verifier side
    // ------------------------------------------------------------------------------------------

    template<typename FieldElementT>
    CommittedTraceVerifier<FieldElementT>::CommittedTraceVerifier(
        MaybeOwnedPtr<const EvaluationDomain> evaluation_domain, size_t n_columns,
        const TableVerifierFactory<FieldElementT> &table_verifier_factory) :
        evaluation_domain_(std::move(evaluation_domain)),
        n_columns_(n_columns), table_verifier_(table_verifier_factory(evaluation_domain_->Size(), n_columns)) {
    }

    template<typename FieldElementT>
    void CommittedTraceVerifier<FieldElementT>::ReadCommitment() {
        table_verifier_->ReadCommitment();
    }

    template<typename FieldElementT>
    std::vector<FieldElementT> CommittedTraceVerifier<FieldElementT>::VerifyDecommitment(
        gsl::span<const std::tuple<uint64_t, uint64_t, size_t>> queries) const {
        const uint64_t trace_length = evaluation_domain_->TraceSize();

        // The commitment items we need to open.
        std::set<RowCol> data_queries;
        for (const auto &[coset_index, offset, column_index] : queries) {
            ASSERT_RELEASE(coset_index < evaluation_domain_->NumCosets(), "Coset index out of range.");
            ASSERT_RELEASE(offset < trace_length, "Coset offset out of range.");
            ASSERT_RELEASE(column_index < n_columns_, "Column index out of range.");
            data_queries.emplace(coset_index * trace_length + offset, column_index);
        }

        // Query results.
        std::map<RowCol, FieldElementT> data_responses =
            table_verifier_->Query(data_queries, {} /* no integrity queries */);

        ASSERT_RELEASE(table_verifier_->VerifyDecommitment(data_responses),
                       "Prover responses did not pass integrity check: Proof rejected.");

        // Allocate storage for responses.
        std::vector<FieldElementT> query_responses;
        query_responses.reserve(queries.size());

        // Place query results at the correct place.
        for (const auto &[coset_index, offset, column_index] : queries) {
            query_responses.push_back(data_responses.at(RowCol(coset_index * trace_length + offset, column_index)));
        }

        return query_responses;
    }
}    // namespace starkware

#endif    // STARKWARE_STARK_COMMITTED_TRACE_H_
