#ifndef STARKWARE_STARK_STARK_H_
#define STARKWARE_STARK_STARK_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "starkware/air/air.h"
#include "starkware/air/trace.h"
#include "starkware/algebra/domains/coset.h"
#include "starkware/algebra/domains/evaluation_domain.h"
#include "starkware/algebra/lde/cached_lde_manager.h"
#include "starkware/algebra/lde/lde_manager.h"
#include "starkware/channel/prover_channel.h"
#include "starkware/channel/verifier_channel.h"
#include "starkware/commitment_scheme/table_prover.h"
#include "starkware/commitment_scheme/table_prover_impl.h"
#include "starkware/commitment_scheme/table_verifier.h"
#include "starkware/composition_polynomial/composition_polynomial.h"
#include "starkware/fri/fri_parameters.h"
#include "starkware/stark/committed_trace.h"
#include "starkware/stark/composition_oracle.h"
#include "starkware/utils/json.h"
#include "starkware/utils/maybe_owned_ptr.h"

namespace starkware {

    struct StarkParameters {
        StarkParameters(size_t n_evaluation_domain_cosets, size_t trace_length, MaybeOwnedPtr<const Air> air,
                        MaybeOwnedPtr<FriParameters> fri_params);

        size_t TraceLength() const {
            return evaluation_domain.TraceSize();
        }
        size_t NumCosets() const {
            return evaluation_domain.NumCosets();
        }
        size_t NumColumns() const {
            return (air->NumColumns());
        }

        static StarkParameters FromJson(const JsonValue &json, MaybeOwnedPtr<const Air> air);

        EvaluationDomain evaluation_domain;
        Coset composition_eval_domain;

        MaybeOwnedPtr<const Air> air;
        MaybeOwnedPtr<FriParameters> fri_params;
    };

    struct StarkProverConfig {
        /*
          Evaluation of composition polynomial on the coset is split to different tasks of size
          constraint_polynomial_task_size each to allow multithreading.
          The larger the task size the lower the amortized threading overhead but this can also affect the
          fragmentation effect in case the number of tasks doesn't divide the coset by a multiple of the
          number of threads in the thread pool.
        */
        uint64_t constraint_polynomial_task_size;

        static StarkProverConfig Default() {
            return {
                /*constraint_polynomial_task_size=*/256,
            };
        }

        static StarkProverConfig FromJson(const JsonValue &json);
    };

    class StarkProver {
    public:
        StarkProver(MaybeOwnedPtr<ProverChannel> channel,
                    MaybeOwnedPtr<TableProverFactory<BaseFieldElement>> base_table_prover_factory,
                    MaybeOwnedPtr<TableProverFactory<ExtensionFieldElement>> extension_table_prover_factory,
                    MaybeOwnedPtr<const StarkParameters> params, MaybeOwnedPtr<const StarkProverConfig> config) :
            channel_(std::move(channel)),
            base_table_prover_factory_(std::move(base_table_prover_factory)),
            extension_table_prover_factory_(std::move(extension_table_prover_factory)), params_(std::move(params)),
            config_(std::move(config)) {
        }

        /*
          Implements the STARK prover side of the protocol given a trace, a constraint system defined in
          an AIR (to verify the Trace's validity), and a set of protocol parameters defining attributes
          such as the required soundness. The prover uses a commitment scheme factory for generating
          commitments and decommitments and a prover channel for sending proof elements and receiving
          field elements from the simulated verifier. The STARK prover uses a Low Degree Test (LDT) prover
          as its main proof engine. The LDT used is FRI.

          The main STARK prover steps are:
          - Perform a Low Degree Extension (LDE) on each column of the trace.
          - Concatenate the LDEs of the columns to form a table (the "main trace"), and commit
            to it.
          - Get a set of random coefficients from the verifier required to create a random linear
            combination of the AIR constraints, called the Constraint Polynomial, of a degree less than
            degree max_constraint_deg.
          - Define the composition of the Constraint Polynomial over the polynomials represented by the
            "main trace" columns as the Composition Polynomial, which is of a degree less than
            comp_deg = max_constraint_deg * "main trace"_column_length.
          - Evaluate the Composition Polynomial on max_constraint_deg cosets, and break the evaluation
            into max_constraint_deg "broken" evaluations on a single coset.
          - Perform a LDE on each of the "broken" evaluations.
          - Concatenate the LDEs of the "broken" evaluations to form a table (call it the "composition
            trace"), and commit to it.
          - Concatenate the original trace with the composition trace into the "final table" and create
            new constraints on this table.
            This is done via Out Of Domain Sampling (OODS). A random field element Z is sent to the prover
            from the verifier, and the prover sends back the entire mask evaluated at Z, and the broken
            polynomials evaluated at Z. The new boundary constraints verify consistency of the elements
            sent by the prover (to check the prover sent the correct evaluations). The boundary
            constraints also check that the original polynomials are of low degree.
          - With the new constraints in hand, create a new composition polynomial of
            "main trace"_column_length degree.
          - Create a virtual oracle (FRI top layer), which decommits queries of the new composition
            polynomial using the previous commitments.
          - Run a LDT prover (e.g. FRI) to prove that the virtual oracle is of the desired low degree,
            also implying low degreeness of all the above polynomials.
        */
        void ProveStark(Trace &&trace);

    private:
        void PerformLowDegreeTest(const CompositionOracleProver &oracle);

        /*
          Creates a CommittedTraceProver from a trace.
          Parameters:
          * trace: The trace to commit on.
          * trace_domain: The domain on which the trace is defined.
          * bit_reverse: Whether the trace should be bit-reversed prior to committing.
        */
        template<typename FieldElementT>
        CommittedTraceProver<FieldElementT> CommitOnTrace(TraceBase<FieldElementT> &&trace, const Coset &trace_domain,
                                                          bool bit_reverse, const std::string &profiling_text);

        CompositionOracleProver OutOfDomainSamplingProve(CompositionOracleProver original_oracle);

        /*
          Validates that the given arguments regarding the trace size are the same as in params_.
        */
        void ValidateTraceSize(size_t n_rows, size_t n_columns);

        MaybeOwnedPtr<ProverChannel> channel_;
        MaybeOwnedPtr<TableProverFactory<BaseFieldElement>> base_table_prover_factory_;
        MaybeOwnedPtr<TableProverFactory<ExtensionFieldElement>> extension_table_prover_factory_;
        MaybeOwnedPtr<const StarkParameters> params_;
        MaybeOwnedPtr<const StarkProverConfig> config_;
    };

    class StarkVerifier {
    public:
        StarkVerifier(MaybeOwnedPtr<VerifierChannel> channel,
                      MaybeOwnedPtr<const TableVerifierFactory<BaseFieldElement>>
                          base_table_verifier_factory,
                      MaybeOwnedPtr<const TableVerifierFactory<ExtensionFieldElement>>
                          extension_table_verifier_factory,
                      MaybeOwnedPtr<const StarkParameters>
                          params) :
            channel_(std::move(channel)),
            base_table_verifier_factory_(std::move(base_table_verifier_factory)),
            extension_table_verifier_factory_(std::move(extension_table_verifier_factory)), params_(std::move(params)) {
        }

        /*
          Implements the STARK verifier side of the protocol given constraint system defined in an AIR (to
          verify the Trace) and a set of protocol parameters definition attributes such as the required
          soundness. The verifier uses a commitment scheme factory for requesting commitments and
          decommitments, and a verifier channel for receiving proof elements from the simulated prover.
          The STARK verifier uses a Low Degree Test (LDT) verifier as its main verification engine. The
          LDT used is FRI.

          The main STARK verifier steps are:
          - Receive a commitment on the trace generated by the prover.
          - Send a set of random coefficients to the prover required to create a random linear combination
            of the AIR constraints, called the Constraint Polynomial of a degree less than degree
            max_constraint_deg.
          - Define the composition of the Constraint Polynomial over the polynomials represented by the
            "main trace" columns as the Composition Polynomial, which is of a degree less than
            comp_deg = max_constraint_deg * "main trace"_column_length.
          - Receive a commitment on the max_constraint_deg polynomials representing the broken composition
            polynomial.
          - Perform OODS - send a random field element Z to the prover, and receive the entire mask
            evaluated at Z, and the max_constraint_deg polynomials representing the broken composition
            polynomial evaluated at Z.
          - Calculate the new AIR constraints and new boundary constraints derived from the OODS in order
            to calculate points of a virtual oracle (FRI top layer).
          - Run a LDT verifier (e.g. FRI) to verify that the virtual oracle is of the desired low degree.

          In case verification fails, an exception is thrown.
        */
        void VerifyStark();

    private:
        /*
          Reads the trace's commitment.
        */
        CommittedTraceVerifier<BaseFieldElement> ReadTraceCommitment(size_t n_columns);

        void PerformLowDegreeTest(const CompositionOracleVerifier &oracle);

        CompositionOracleVerifier OutOfDomainSamplingVerify(CompositionOracleVerifier original_oracle);

        MaybeOwnedPtr<VerifierChannel> channel_;
        MaybeOwnedPtr<const TableVerifierFactory<BaseFieldElement>> base_table_verifier_factory_;
        MaybeOwnedPtr<const TableVerifierFactory<ExtensionFieldElement>> extension_table_verifier_factory_;
        MaybeOwnedPtr<const StarkParameters> params_;

        std::unique_ptr<CompositionPolynomial> composition_polynomial_;
    };

    namespace {

        // ------------------------------------------------------------------------------------------
        //  Prover and Verifier common code
        // ------------------------------------------------------------------------------------------

        std::unique_ptr<CompositionPolynomial>
            CreateCompositionPolynomial(Channel *channel, const BaseFieldElement &trace_generator, const Air &air) {
            AnnotationScope scope(channel, "Constraint Coefficients");
            size_t num_random_coefficients_required = air.NumRandomCoefficients();
            std::vector<ExtensionFieldElement> random_coefficients = ExtensionFieldElement::UninitializedVector(0);
            // Get random coefficients from the verifier.
            for (size_t i = 0; i < num_random_coefficients_required; ++i) {
                random_coefficients.push_back(channel->GetRandomFieldElementFromVerifier(std::to_string(i)));
            }
            return air.CreateCompositionPolynomial(trace_generator, random_coefficients);
        }

        /*
          Returns a vector of pairs (coset_index, offset) such that:
              fri_domain[fri_query] = evaluation_domain.ElementByIndex(coset_index, offset).
        */
        std::vector<std::pair<uint64_t, uint64_t>>
            FriQueriesToEvaluationDomainQueries(const std::vector<uint64_t> &fri_queries, const uint64_t trace_length) {
            std::vector<std::pair<uint64_t, uint64_t>> queries;
            queries.reserve(fri_queries.size());
            for (uint64_t fri_query : fri_queries) {
                const uint64_t coset_index = fri_query / trace_length;
                const uint64_t offset = fri_query & (trace_length - 1);
                queries.emplace_back(coset_index, offset);
            }
            return queries;
        }

        /*
          Computes the FRI degree bound from last_layer_degree_bound and fri_step_list.
        */
        uint64_t GetFriExpectedDegreeBound(const FriParameters &fri_params) {
            uint64_t expected_bound = fri_params.last_layer_degree_bound;
            for (const size_t fri_step : fri_params.fri_step_list) {
                expected_bound *= Pow2(fri_step);
            }
            return expected_bound;
        }

    }    // namespace

    // ------------------------------------------------------------------------------------------
    //  StarkParameters
    // ------------------------------------------------------------------------------------------

    static Coset GenerateCompositionDomain(const Air &air) {
        const size_t size = air.GetCompositionPolynomialDegreeBound();
        return Coset(size, BaseFieldElement::Generator());
    }

    StarkParameters::StarkParameters(size_t n_evaluation_domain_cosets, size_t trace_length,
                                     MaybeOwnedPtr<const Air> air, MaybeOwnedPtr<FriParameters> fri_params) :
        evaluation_domain(trace_length, n_evaluation_domain_cosets),
        composition_eval_domain(GenerateCompositionDomain(*air)), air(std::move(air)),
        fri_params(std::move(fri_params)) {
        ASSERT_RELEASE(IsPowerOfTwo(n_evaluation_domain_cosets), "The number of cosets must be a power of 2.");

        // Check that the fri_step_list and last_layer_degree_bound parameters are consistent with the
        // trace length. This is the expected degree in the out of domain sampling stage.
        const uint64_t expected_fri_degree_bound = GetFriExpectedDegreeBound(*this->fri_params);
        const uint64_t stark_degree_bound = trace_length;
        ASSERT_RELEASE(expected_fri_degree_bound == stark_degree_bound,
                       "FRI parameters do not match stark degree bound. Expected FRI degree from "
                       "FriParameters: " +
                           std::to_string(expected_fri_degree_bound) +
                           ". STARK: " + std::to_string(stark_degree_bound) + ".");
    }

    StarkParameters StarkParameters::FromJson(const JsonValue &json, MaybeOwnedPtr<const Air> air) {
        const uint64_t trace_length = air->TraceLength();
        const size_t log_trace_length = SafeLog2(trace_length);
        const size_t log_n_cosets = json["log_n_cosets"].AsSizeT();
        const uint64_t log_max_constraint_degree =
            SafeLog2(SafeDiv(air->GetCompositionPolynomialDegreeBound(), trace_length));
        ASSERT_RELEASE(log_n_cosets >= log_max_constraint_degree,
                       "The blowup factor must be at least " + std::to_string(log_max_constraint_degree) + ".");
        ASSERT_RELEASE(log_n_cosets <= 10, "The blowup factor cannot be greater than 1024 (log_n_cosets <= 10).");
        const size_t n_cosets = Pow2(log_n_cosets);

        FriParameters fri_params = FriParameters::FromJson(json["fri"], log_trace_length, log_n_cosets);

        return StarkParameters(n_cosets, trace_length, std::move(air), UseMovedValue(std::move(fri_params)));
    }

    // ------------------------------------------------------------------------------------------
    //  StarkProverConfig
    // ------------------------------------------------------------------------------------------

    StarkProverConfig StarkProverConfig::FromJson(const JsonValue &json) {
        const uint64_t constraint_polynomial_task_size = json["constraint_polynomial_task_size"].AsUint64();

        return {
            /*constraint_polynomial_task_size=*/constraint_polynomial_task_size,
        };
    }

    // ------------------------------------------------------------------------------------------
    //  Prover
    // ------------------------------------------------------------------------------------------

    void StarkProver::PerformLowDegreeTest(const CompositionOracleProver &oracle) {
        AnnotationScope scope(channel_.get(), "FRI");

        // Check that the fri_step_list and last_layer_degree_bound parameters are consistent with the
        // oracle degree bound.
        const uint64_t expected_fri_degree_bound = GetFriExpectedDegreeBound(*params_->fri_params);
        const uint64_t oracle_degree_bound = oracle.ConstraintsDegreeBound() * params_->TraceLength();
        ASSERT_RELEASE(expected_fri_degree_bound == oracle_degree_bound,
                       "FRI parameters do not match oracle degree. Expected FRI degree from "
                       "FriParameters: " +
                           std::to_string(expected_fri_degree_bound) +
                           ". STARK: " + std::to_string(oracle_degree_bound));

        ProfilingBlock profiling_block("FRI virtual oracle computation");
        // Evaluate composition polynomial.
        std::vector<ExtensionFieldElement> composition_polynomial_evaluation =
            oracle.EvalComposition(config_->constraint_polynomial_task_size, params_->NumCosets());
        profiling_block.CloseBlock();

        ProfilingBlock fri_profiling_block("FRI");
        // Prepare FRI.
        FriProver::FirstLayerCallback first_layer_queries_callback =
            [this, &oracle](const std::vector<uint64_t> &fri_queries) {
                ProfilingBlock profiling_block("FRI virtual oracle callback");
                AnnotationScope scope(channel_.get(), "Virtual Oracle");
                const auto queries = FriQueriesToEvaluationDomainQueries(fri_queries, params_->TraceLength());
                oracle.DecommitQueries(queries);
            };

        FriProver fri_prover(UseOwned(channel_), UseOwned(extension_table_prover_factory_),
                             UseOwned(params_->fri_params), std::move(composition_polynomial_evaluation),
                             UseOwned(&first_layer_queries_callback));
        fri_prover.ProveFri();
    }

    template<typename FieldElementT>
    CommittedTraceProver<FieldElementT> StarkProver::CommitOnTrace(TraceBase<FieldElementT> &&trace,
                                                                   const Coset &trace_domain, bool bit_reverse,
                                                                   const std::string &profiling_text) {
        ProfilingBlock commit_block(profiling_text);
        AnnotationScope scope(channel_.get(), "Commit on Trace");

        TableProverFactory<FieldElementT> *table_prover_factory;
        if constexpr (std::is_same_v<FieldElementT, ExtensionFieldElement>) {    // NOLINT
            table_prover_factory = extension_table_prover_factory_.get();
        } else {    // NOLINT: Suppress readability-else-after-return after if constexpr.
            table_prover_factory = base_table_prover_factory_.get();
        }

        CommittedTraceProver<FieldElementT> committed_trace(UseOwned(&params_->evaluation_domain), trace.Width(),
                                                            *table_prover_factory);
        committed_trace.Commit(std::move(trace), trace_domain, bit_reverse);
        return committed_trace;
    }

    CompositionOracleProver StarkProver::OutOfDomainSamplingProve(CompositionOracleProver original_oracle) {
        AnnotationScope scope(channel_.get(), "Out Of Domain Sampling");

        const size_t n_breaks = original_oracle.ConstraintsDegreeBound();

        ProfilingBlock composition_block("Composition polynomial computation");
        const std::vector<ExtensionFieldElement> composition_eval = original_oracle.EvalComposition(
            config_->constraint_polynomial_task_size, original_oracle.ConstraintsDegreeBound());
        composition_block.CloseBlock();

        ProfilingBlock breaker_block("Polynomial breaker");
        // Break the evaluation of the composition polynomial on n_breaks cosets to evaluations of
        // n_breaks polynomials on a single coset.
        // NOLINTNEXTLINE.
        auto [uncommitted_composition_trace, composition_trace_domain] =
            oods::BreakCompositionPolynomial(composition_eval, n_breaks, params_->composition_eval_domain);
        breaker_block.CloseBlock();

        // The resulting n_breaks evaluations are on a coset which may have a different offset than the
        // trace. composition_trace_domain represents that coset. It should have the same basis, but a
        // different offset than the trace.
        ASSERT_RELEASE(params_->evaluation_domain.TraceSize() == composition_trace_domain.Size(),
                       "Trace and Composition do no match.");

        // Create a LDE of the composition trace and commit to it.
        auto composition_trace = CommitOnTrace(std::move(uncommitted_composition_trace), composition_trace_domain,
                                               false, "Commit on composition");

        auto boundary_conditions = oods::ProveOods(channel_.get(), original_oracle, composition_trace);
        auto boundary_air = oods::CreateBoundaryAir(params_->evaluation_domain.TraceSize(),
                                                    original_oracle.Width() + n_breaks, std::move(boundary_conditions));

        // Move the trace from original_oracle.
        auto trace = std::move(original_oracle).MoveTrace();
        trace->FinalizeEval();
        composition_trace.FinalizeEval();

        auto oods_composition_polynomial =
            CreateCompositionPolynomial(channel_.get(), params_->evaluation_domain.TraceGenerator(), *boundary_air);

        const auto boundary_mask = boundary_air->GetMask();
        CompositionOracleProver oods_virtual_oracle(
            UseOwned(&params_->evaluation_domain), std::move(trace), UseMovedValue(std::move(composition_trace)),
            boundary_mask, TakeOwnershipFrom(std::move(boundary_air)),
            TakeOwnershipFrom(std::move(oods_composition_polynomial)), channel_.get());

        return oods_virtual_oracle;
    }

    void StarkProver::ValidateTraceSize(const size_t n_rows, const size_t n_columns) {
        ASSERT_RELEASE(params_->evaluation_domain.TraceSize() == n_rows,
                       "Trace length parameter " + std::to_string(n_rows) +
                           " is inconsistent with actual trace length " +
                           std::to_string(params_->evaluation_domain.TraceSize()) + ".");
        ASSERT_RELEASE(params_->air->NumColumns() == n_columns,
                       "Trace width parameter is inconsistent with actual trace width.");
    }

    void StarkProver::ProveStark(Trace &&trace) {
        ValidateTraceSize(trace.Length(), trace.Width());
        AnnotationScope scope(channel_.get(), "STARK");
        MaybeOwnedPtr<CommittedTraceProverBase<BaseFieldElement>> committed_trace;
        // Add committed trace (create LDE of the trace and commit to it).
        {
            AnnotationScope scope(channel_.get(), "Original");
            const Coset trace_domain(trace.Length(), BaseFieldElement::One());
            committed_trace = UseMovedValue(CommitOnTrace(std::move(trace), trace_domain, true, "Commit on trace"));
        }

        const Air *current_air = (params_->air).get();

        // Create composition polynomial from AIR.
        std::unique_ptr<CompositionPolynomial> composition_polynomial;
        {
            AnnotationScope scope(channel_.get(), "Original");
            composition_polynomial =
                CreateCompositionPolynomial(channel_.get(), params_->evaluation_domain.TraceGenerator(), *current_air);
        }

        CompositionOracleProver composition_oracle(UseOwned(&params_->evaluation_domain), std::move(committed_trace),
                                                   nullptr, current_air->GetMask(), UseOwned(current_air),
                                                   UseOwned(composition_polynomial.get()), channel_.get());

        const CompositionOracleProver oods_composition_oracle = OutOfDomainSamplingProve(std::move(composition_oracle));

        PerformLowDegreeTest(oods_composition_oracle);
    }

    // ------------------------------------------------------------------------------------------
    //  Verifier
    // ------------------------------------------------------------------------------------------

    CommittedTraceVerifier<BaseFieldElement> StarkVerifier::ReadTraceCommitment(const size_t n_columns) {
        CommittedTraceVerifier<BaseFieldElement> trace_verifier(UseOwned(&params_->evaluation_domain), n_columns,
                                                                *base_table_verifier_factory_);
        AnnotationScope scope(channel_.get(), "Commit on Trace");
        trace_verifier.ReadCommitment();
        return trace_verifier;
    }

    void StarkVerifier::PerformLowDegreeTest(const CompositionOracleVerifier &oracle) {
        AnnotationScope scope(channel_.get(), "FRI");

        // Check that the fri_step_list and last_layer_degree_bound parameters are consistent with the
        // oracle degree bound.
        const uint64_t expected_fri_degree_bound = GetFriExpectedDegreeBound(*params_->fri_params);
        const uint64_t oracle_degree_bound = oracle.ConstraintsDegreeBound() * params_->TraceLength();
        ASSERT_RELEASE(expected_fri_degree_bound == oracle_degree_bound,
                       "FRI parameters do not match oracle degree. Expected FRI degree from "
                       "FriParameters: " +
                           std::to_string(expected_fri_degree_bound) +
                           ". STARK: " + std::to_string(oracle_degree_bound) + ".");

        // Prepare FRI.
        FriVerifier::FirstLayerCallback first_layer_queries_callback =
            [this, &oracle](const std::vector<uint64_t> &fri_queries) {
                AnnotationScope scope(channel_.get(), "Virtual Oracle");
                const auto queries = FriQueriesToEvaluationDomainQueries(fri_queries, params_->TraceLength());
                return oracle.VerifyDecommitment(queries);
            };
        FriVerifier fri_verifier(UseOwned(channel_), UseOwned(extension_table_verifier_factory_),
                                 UseOwned(params_->fri_params), UseOwned(&first_layer_queries_callback));
        fri_verifier.VerifyFri();
    }

    CompositionOracleVerifier StarkVerifier::OutOfDomainSamplingVerify(CompositionOracleVerifier original_oracle) {
        AnnotationScope scope(channel_.get(), "Out Of Domain Sampling");
        CommittedTraceVerifier<ExtensionFieldElement> composition_trace(UseOwned(&params_->evaluation_domain),
                                                                        original_oracle.ConstraintsDegreeBound(),
                                                                        *extension_table_verifier_factory_);
        {
            AnnotationScope scope(channel_.get(), "Commit on Trace");
            composition_trace.ReadCommitment();
        }

        auto boundary_conditions = oods::VerifyOods(params_->evaluation_domain, channel_.get(), original_oracle,
                                                    params_->composition_eval_domain);

        auto boundary_air = oods::CreateBoundaryAir(params_->evaluation_domain.TraceSize(),
                                                    original_oracle.Width() + original_oracle.ConstraintsDegreeBound(),
                                                    std::move(boundary_conditions));
        {
            auto oods_composition_polynomial =
                CreateCompositionPolynomial(channel_.get(), params_->evaluation_domain.TraceGenerator(), *boundary_air);

            auto trace = std::move(original_oracle).MoveTrace();
            const auto boundary_mask = boundary_air->GetMask();
            CompositionOracleVerifier composition_oracle(
                UseOwned(&params_->evaluation_domain), std::move(trace), UseMovedValue(std::move(composition_trace)),
                boundary_mask, TakeOwnershipFrom(std::move(boundary_air)),
                TakeOwnershipFrom(std::move(oods_composition_polynomial)), channel_.get());

            return composition_oracle;
        }
    }

    void StarkVerifier::VerifyStark() {
        AnnotationScope scope(channel_.get(), "STARK");
        MaybeOwnedPtr<const CommittedTraceVerifierBase<BaseFieldElement>> trace;
        // Create a CommittedTraceVerifier for the decommitment.
        {
            AnnotationScope scope(channel_.get(), "Original");
            CommittedTraceVerifier<BaseFieldElement> trace_verifier(ReadTraceCommitment(params_->air->NumColumns()));
            trace = UseMovedValue(std::move(trace_verifier));
        }

        MaybeOwnedPtr<const Air> current_air(UseOwned(params_->air));

        // Create composition polynomial from AIR.
        {
            AnnotationScope scope(channel_.get(), "Original");
            composition_polynomial_ =
                CreateCompositionPolynomial(channel_.get(), params_->evaluation_domain.TraceGenerator(), *current_air);
        }
        CompositionOracleVerifier composition_oracle(
            UseOwned(&params_->evaluation_domain), std::move(trace), nullptr, current_air->GetMask(),
            UseOwned(current_air.get()), TakeOwnershipFrom(std::move(composition_polynomial_)), channel_.get());

        const CompositionOracleVerifier oods_composition_oracle =
            OutOfDomainSamplingVerify(std::move(composition_oracle));

        PerformLowDegreeTest(oods_composition_oracle);
    }

}    // namespace starkware

#endif    // STARKWARE_STARK_STARK_H_
