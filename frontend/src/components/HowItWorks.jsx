const STEPS = [
  {
    title: 'Synthetic one-way traffic',
    detail: 'Flow records arrive from a simulated unidirectional link',
  },
  {
    title: 'Passive read-only analysis',
    detail: 'Each record is inspected, never altered or answered',
  },
  {
    title: 'Rule-based detection',
    detail: 'Three plain-English rules, no machine learning',
  },
  {
    title: 'Live alert',
    detail: 'The reason it fired is shown on this dashboard instantly',
  },
]

/** The architecture explainer shown to judges at the bottom of the page. */
export default function HowItWorks() {
  return (
    <section className="panel how-panel" aria-labelledby="how-heading">
      <h2 id="how-heading" className="panel-title">
        How this works
      </h2>

      <ol className="how-steps">
        {STEPS.map((step, index) => (
          <li className="how-step" key={step.title}>
            <span className="how-step-number" aria-hidden="true">
              {index + 1}
            </span>
            <span className="how-step-body">
              <span className="how-step-title">{step.title}</span>
              <span className="how-step-detail">{step.detail}</span>
            </span>
            {index < STEPS.length - 1 && (
              <span className="how-arrow" aria-hidden="true">
                &rarr;
              </span>
            )}
          </li>
        ))}
      </ol>

      <p className="how-note">
        This system never sends data back into the monitored network &mdash; it
        only observes and analyzes, matching the constraints of a unidirectional
        link.
      </p>
    </section>
  )
}
