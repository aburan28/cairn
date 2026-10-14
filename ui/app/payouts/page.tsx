"use client";

import { useEffect, useMemo, useState } from "react";
import { useNode } from "@/components/hooks";
import { CopyButton, EmptyState, Note, PageHeader } from "@/components/ui";
import { fetchObjectives, type Objective } from "@/lib/objectives";
import { draftReceipt, fetchPayoutPreview, quotePayouts, type PayoutPreview } from "@/lib/payouts";
import { objectiveTitle } from "@/lib/title";

const ASSETS = [
  { id: "bitcoin:mainnet", label: "Bitcoin (mainnet)", unit: "satoshis" },
  { id: "eip155:8453/usdc", label: "USDC (Base)", unit: "millionths of a USDC" },
] as const;

/** What a funder could pay outside Cairn, using the log's verified split. */
export default function Page() {
  const base = useNode();
  const [objectives, setObjectives] = useState<Objective[]>([]);
  const [selected, setSelected] = useState("");
  const [preview, setPreview] = useState<PayoutPreview | null>(null);
  const [asset, setAsset] = useState<(typeof ASSETS)[number]["id"]>("bitcoin:mainnet");
  const [amountText, setAmountText] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (base === null) return;
    let current = true;
    fetchObjectives(base)
      .then((items) => {
        if (!current) return;
        setObjectives(items);
        const requested = new URLSearchParams(window.location.search).get("id");
        setSelected(items.find((item) => item.id === requested)?.id ?? items[0]?.id ?? "");
      })
      .catch((failure) => { if (current) setError(String(failure)); });
    return () => { current = false; };
  }, [base]);

  useEffect(() => {
    if (base === null || !selected) return;
    let current = true;
    setPreview(null);
    fetchPayoutPreview(base, selected)
      .then((value) => { if (current) { setPreview(value); setError(null); } })
      .catch((failure) => { if (current) setError(String(failure)); });
    return () => { current = false; };
  }, [base, selected]);

  const quote = useMemo(() => {
    if (!preview || !amountText) return null;
    try { return { value: quotePayouts(preview, amountText), error: null }; }
    catch (failure) { return { value: null, error: String(failure) }; }
  }, [preview, amountText]);
  const denomination = ASSETS.find((item) => item.id === asset)!;

  return (
    <>
      <PageHeader
        title="External bounties"
        subtitle="See who earned the funded units, then plan a payment from your own wallet. Cairn does not hold or send cryptocurrency."
      />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <section className="card card-pad">
          <h2 className="text-[15px] font-semibold text-ink">Choose a challenge</h2>
          <p className="mt-1 text-[12.5px] text-ink-2">The split comes from settlements and citations in this node&apos;s log.</p>
          <select
            className="field mt-4 w-full"
            aria-label="Challenge"
            value={selected}
            onChange={(event) => setSelected(event.target.value)}
          >
            {objectives.length === 0 && <option value="">No challenge loaded</option>}
            {objectives.map((item) => <option key={item.id} value={item.id}>{objectiveTitle(item)}</option>)}
          </select>
          {preview && (
            <div className="mt-5 grid grid-cols-2 gap-3 border-t border-edge pt-4 text-[13px]">
              <div><div className="text-ink-3">Funded in Cairn</div><div className="mt-1 font-semibold text-ink">{BigInt(preview.reward_units).toLocaleString()} units</div></div>
              <div><div className="text-ink-3">Settled so far</div><div className="mt-1 font-semibold text-ink">{BigInt(preview.settled_units).toLocaleString()} units</div></div>
            </div>
          )}
          <div className="mt-5 border-t border-edge pt-4">
            <h3 className="text-[13px] font-semibold text-ink">Plan an outside payment</h3>
            <p className="mt-1 text-[12px] text-ink-2">These terms stay in this page. No deposit or transfer happens here.</p>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <label className="text-[12px] text-ink-2">Asset
                <select className="field mt-1 w-full" value={asset} onChange={(event) => setAsset(event.target.value as typeof asset)}>
                  {ASSETS.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
                </select>
              </label>
              <label className="text-[12px] text-ink-2">Amount in {denomination.unit}
                <input className="field field-mono mt-1 w-full" inputMode="numeric" placeholder="e.g. 1000000"
                  maxLength={32} value={amountText} onChange={(event) => setAmountText(event.target.value.trim())} />
              </label>
            </div>
            {quote?.error && <p className="mt-2 text-[12px] text-bad">{quote.error}</p>}
          </div>
        </section>

        <section className="card card-pad">
          <h2 className="text-[15px] font-semibold text-ink">Contributors</h2>
          {error && <Note title="Could not read attribution" tone="bad">{error}</Note>}
          {!error && !preview && <p className="mt-3 text-[13px] text-ink-2">Reading settled work…</p>}
          {preview && preview.payees.length === 0 && <EmptyState title="Nothing settled yet">Contributors appear after verified work settles in the log.</EmptyState>}
          {preview && preview.payees.length > 0 && (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-left text-[12.5px]">
                <thead><tr className="border-b border-edge text-ink-3"><th className="py-2 pr-3 font-medium">Identity</th><th className="py-2 pr-3 text-right font-medium">Earned units</th>{quote?.value && <th className="py-2 text-right font-medium">Payment preview</th>}</tr></thead>
                <tbody>{preview.payees.map((payee) => {
                  const payment = quote?.value?.rows.find((row) => row.identity === payee.identity)?.amount;
                  return <tr key={payee.identity} className="border-b border-edge/60">
                    <td className="mono py-2 pr-3" title={payee.identity}>{payee.identity.length > 22 ? `${payee.identity.slice(0, 12)}…${payee.identity.slice(-8)}` : payee.identity}</td>
                    <td className="mono py-2 pr-3 text-right">{BigInt(payee.units).toLocaleString()}</td>
                    {quote?.value && <td className="mono py-2 text-right">{payment?.toLocaleString() ?? "0"}</td>}
                  </tr>;
                })}</tbody>
              </table>
            </div>
          )}
          {quote?.value && <p className="mt-3 text-[12px] text-ink-2">Unallocated: {quote.value.unallocated.toLocaleString()} {denomination.unit}. This includes work still open and integer rounding.</p>}
          {preview && quote?.value && (
            <div className="mt-3 flex items-center gap-2 text-[12px] text-ink-2">
              <CopyButton value={draftReceipt(preview, asset, amountText)} />
              Copy draft receipt, including this log head
            </div>
          )}
          <p className="mt-4 border-t border-edge pt-4 text-[12px] leading-relaxed text-ink-2">
            This is an attribution preview under the default citation policy. A payment needs the contributor&apos;s verified receiving address and a separately funded arrangement. No address or on-chain escrow is bound to this log yet.
          </p>
        </section>
      </div>
    </>
  );
}
