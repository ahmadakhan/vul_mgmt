import type { EmailRecipient } from '../src/types/index.ts';

/** One physical mailbox receives no more than one job from a queue pass.
 * When duplicate configurations exist, prefer the widest subscription; break
 * ties in favour of the Security team. The selected row owns the claim.
 */
export function uniqueEnabledEmailRecipients(recipients: readonly EmailRecipient[]): EmailRecipient[] {
  const byAddress = new Map<string, EmailRecipient>();
  const tierRank = (recipient: EmailRecipient): number =>
    recipient.subscriptionTier === 'ALL_SEVERITIES' ? 3 :
    recipient.subscriptionTier === 'CRITICAL_HIGH_ONLY' ? 2 : 1;
  const groupRank = (recipient: EmailRecipient): number =>
    recipient.deliveryGroup === 'SECURITY_TEAM' ? 2 :
    recipient.deliveryGroup === 'EVERYONE' ? 0 : 1;
  for (const recipient of recipients) {
    if (!recipient.enabled) continue;
    const address = recipient.email?.trim().toLowerCase();
    if (!address) continue;
    const previous = byAddress.get(address);
    if (!previous || tierRank(recipient) > tierRank(previous) ||
        (tierRank(recipient) === tierRank(previous) &&
         (groupRank(recipient) > groupRank(previous) ||
          groupRank(recipient) === groupRank(previous) && recipient.id.localeCompare(previous.id) < 0))) {
      byAddress.set(address, recipient);
    }
  }
  return [...byAddress.values()].sort((a, b) =>
    a.email.toLowerCase().localeCompare(b.email.toLowerCase()) || a.id.localeCompare(b.id));
}
