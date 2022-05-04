#ifndef STARKWARE_STARK_UTILS_H_
#define STARKWARE_STARK_UTILS_H_

#include "starkware/channel/prover_channel.h"
#include "starkware/commitment_scheme/table_prover.h"

namespace starkware {

    template<typename FieldElementT>
    TableProverFactory<FieldElementT> GetTableProverFactory(ProverChannel *channel) {
        return [channel](size_t n_segments, uint64_t n_rows_per_segment,
                         size_t n_columns) -> std::unique_ptr<TableProver<FieldElementT>> {
            auto packaging_commitment_scheme = MakeCommitmentSchemeProver(FieldElementT::SizeInBytes() * n_columns,
                                                                          n_rows_per_segment, n_segments, channel);

            return std::make_unique<TableProverImpl<FieldElementT>>(
                n_columns, UseMovedValue(std::move(packaging_commitment_scheme)), channel);
        };
    }

}    // namespace starkware

#include "starkware/stark/utils.inl"

#endif    // STARKWARE_STARK_UTILS_H_
