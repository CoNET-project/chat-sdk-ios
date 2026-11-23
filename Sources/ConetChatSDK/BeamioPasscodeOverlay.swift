#if os(iOS) && canImport(UIKit)
import UIKit

extension UIColor {
	/// `#RRGGBB` or `#RRGGBBAA`.
	convenience init(passcodeHex hex: String) {
		var h = hex
		if h.hasPrefix("#") { h.removeFirst() }
		var v: UInt64 = 0
		Scanner(string: h).scanHexInt64(&v)
		let hasAlpha = h.count == 8
		let r = CGFloat((v >> (hasAlpha ? 24 : 16)) & 0xff) / 255
		let g = CGFloat((v >> (hasAlpha ? 16 : 8)) & 0xff) / 255
		let b = CGFloat((v >> (hasAlpha ? 8 : 0)) & 0xff) / 255
		let a = hasAlpha ? CGFloat(v & 0xff) / 255 : 1
		self.init(red: r, green: g, blue: b, alpha: a)
	}
}

/// The native passcode input layer (option A). The digits are taken here, not in the WebView. They are kept as
/// bytes and wiped on submit and on dismissal. While the screen is being captured or recorded, the input is hidden.
///
/// Limit: iOS cannot stop a screenshot. A screenshot shows the dots only, never the digits.
public final class BeamioPasscodeOverlayController: UIViewController {
	public var onFinish: ((BeamioPasscodeRunResult) -> Void)?

	private let runner: BeamioPasscodeRunner
	private let copy: [String: String]
	private var digits: [UInt8] = []
	private var finished = false

	private let titleLabel = UILabel()
	private let hintLabel = UILabel()
	private let dotsStack = UIStackView()
	private let keypad = UIStackView()
	private let confirmButton = UIButton(type: .system)
	private let cover = UIView()

	/// `copy` holds the texts the PWA provides (title, hint, mismatch, wrong, policy, cooldown, cancel). Not secret.
	public init(runner: BeamioPasscodeRunner, copy: [String: String]) {
		self.runner = runner
		self.copy = copy
		super.init(nibName: nil, bundle: nil)
		modalPresentationStyle = .fullScreen
	}

	@available(*, unavailable)
	public required init?(coder: NSCoder) { fatalError("not used") }

	deinit {
		BeamioNativeWallet.wipe(&digits)
	}

	public override func viewDidLoad() {
		super.viewDidLoad()
		view.backgroundColor = UIColor(passcodeHex: BeamioPasscodeTokens.colors["bg"] ?? "#071126")
		buildLayout()
		NotificationCenter.default.addObserver(self, selector: #selector(captureChanged),
		                                       name: UIScreen.capturedDidChangeNotification, object: nil)
		captureChanged()
		refresh()
	}

	public override func viewWillDisappear(_ animated: Bool) {
		super.viewWillDisappear(animated)
		if !finished { _ = runner.cancel() }
	}

	// MARK: - Layout

	private func buildLayout() {
		let fg = UIColor(passcodeHex: BeamioPasscodeTokens.colors["fg"] ?? "#FFFFFF")
		let muted = UIColor(passcodeHex: BeamioPasscodeTokens.colors["fgMuted"] ?? "#FFFFFFBF")
		titleLabel.font = .systemFont(ofSize: BeamioPasscodeTokens.titleSize, weight: .semibold)
		titleLabel.textColor = fg
		titleLabel.textAlignment = .center
		titleLabel.numberOfLines = 0
		hintLabel.font = .systemFont(ofSize: BeamioPasscodeTokens.bodySize)
		hintLabel.textColor = muted
		hintLabel.textAlignment = .center
		hintLabel.numberOfLines = 0

		dotsStack.axis = .horizontal
		dotsStack.spacing = BeamioPasscodeTokens.dotGap
		dotsStack.distribution = .equalSpacing
		for _ in 0 ..< BeamioPasscodeTokens.maxDigits {
			let dot = UIView()
			dot.layer.cornerRadius = BeamioPasscodeTokens.dotSize / 2
			dot.layer.borderWidth = 1
			dot.layer.borderColor = fg.cgColor
			dot.tag = 1
			dot.translatesAutoresizingMaskIntoConstraints = false
			dot.widthAnchor.constraint(equalToConstant: BeamioPasscodeTokens.dotSize).isActive = true
			dot.heightAnchor.constraint(equalToConstant: BeamioPasscodeTokens.dotSize).isActive = true
			dotsStack.addArrangedSubview(dot)
		}

		keypad.axis = .vertical
		keypad.spacing = 12
		keypad.alignment = .center
		for row in 0 ..< BeamioPasscodeTokens.gridRows {
			let rowStack = UIStackView()
			rowStack.axis = .horizontal
			rowStack.spacing = 12
			for col in 0 ..< BeamioPasscodeTokens.gridCols {
				let label = BeamioPasscodeTokens.gridLabels[row * BeamioPasscodeTokens.gridCols + col]
				rowStack.addArrangedSubview(keyButton(label: label))
			}
			keypad.addArrangedSubview(rowStack)
		}

		confirmButton.setTitle(copy["confirm"] ?? "OK", for: .normal)
		confirmButton.titleLabel?.font = .systemFont(ofSize: BeamioPasscodeTokens.bodySize, weight: .semibold)
		confirmButton.setTitleColor(UIColor(passcodeHex: BeamioPasscodeTokens.colors["onAccent"] ?? "#071126"), for: .normal)
		confirmButton.backgroundColor = UIColor(passcodeHex: BeamioPasscodeTokens.colors["accent"] ?? "#FFFFFF")
		confirmButton.layer.cornerRadius = 22
		confirmButton.heightAnchor.constraint(greaterThanOrEqualToConstant: BeamioPasscodeTokens.touchMinTarget).isActive = true
		confirmButton.addTarget(self, action: #selector(confirmTapped), for: .touchUpInside)

		let cancel = UIButton(type: .system)
		cancel.setTitle(copy["cancel"] ?? "Cancel", for: .normal)
		cancel.setTitleColor(muted, for: .normal)
		cancel.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)

		let stack = UIStackView(arrangedSubviews: [titleLabel, hintLabel, dotsStack, keypad, confirmButton, cancel])
		stack.axis = .vertical
		stack.spacing = 20
		stack.alignment = .center
		stack.translatesAutoresizingMaskIntoConstraints = false
		view.addSubview(stack)
		NSLayoutConstraint.activate([
			stack.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 24),
			stack.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -24),
			stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
			confirmButton.widthAnchor.constraint(equalToConstant: 240),
		])

		cover.backgroundColor = UIColor(passcodeHex: BeamioPasscodeTokens.colors["bg"] ?? "#071126")
		cover.isHidden = true
		cover.translatesAutoresizingMaskIntoConstraints = false
		let coverLabel = UILabel()
		coverLabel.text = copy["captured"] ?? "Input is hidden while the screen is recorded."
		coverLabel.textColor = fg
		coverLabel.numberOfLines = 0
		coverLabel.textAlignment = .center
		coverLabel.translatesAutoresizingMaskIntoConstraints = false
		cover.addSubview(coverLabel)
		view.addSubview(cover)
		NSLayoutConstraint.activate([
			cover.topAnchor.constraint(equalTo: view.topAnchor), cover.bottomAnchor.constraint(equalTo: view.bottomAnchor),
			cover.leadingAnchor.constraint(equalTo: view.leadingAnchor), cover.trailingAnchor.constraint(equalTo: view.trailingAnchor),
			coverLabel.centerXAnchor.constraint(equalTo: cover.centerXAnchor), coverLabel.centerYAnchor.constraint(equalTo: cover.centerYAnchor),
			coverLabel.leadingAnchor.constraint(greaterThanOrEqualTo: cover.leadingAnchor, constant: 24),
		])
	}

	private func keyButton(label: String) -> UIView {
		guard !label.isEmpty else {
			let spacer = UIView()
			spacer.widthAnchor.constraint(equalToConstant: BeamioPasscodeTokens.keyWidth).isActive = true
			spacer.heightAnchor.constraint(equalToConstant: BeamioPasscodeTokens.keyHeight).isActive = true
			return spacer
		}
		let button = UIButton(type: .system)
		button.setTitle(label == "delete" ? "⌫" : label, for: .normal)
		button.titleLabel?.font = .systemFont(ofSize: BeamioPasscodeTokens.titleSize, weight: .medium)
		button.setTitleColor(UIColor(passcodeHex: BeamioPasscodeTokens.colors["fg"] ?? "#FFFFFF"), for: .normal)
		button.backgroundColor = UIColor(passcodeHex: BeamioPasscodeTokens.colors["surface"] ?? "#FFFFFF1A")
		button.layer.cornerRadius = BeamioPasscodeTokens.keyRadius
		button.layer.borderWidth = 1
		button.layer.borderColor = UIColor(passcodeHex: BeamioPasscodeTokens.colors["border"] ?? "#FFFFFF26").cgColor
		button.widthAnchor.constraint(equalToConstant: BeamioPasscodeTokens.keyWidth).isActive = true
		button.heightAnchor.constraint(equalToConstant: BeamioPasscodeTokens.keyHeight).isActive = true
		button.accessibilityLabel = label == "delete" ? (copy["delete"] ?? "Delete") : label
		if label == "delete" {
			button.addTarget(self, action: #selector(deleteTapped), for: .touchUpInside)
		} else {
			button.addTarget(self, action: #selector(digitTapped(_:)), for: .touchUpInside)
		}
		button.tag = Int(label) ?? -1
		return button
	}

	// MARK: - Input

	@objc private func digitTapped(_ sender: UIButton) {
		guard digits.count < BeamioPasscodeTokens.maxDigits, (0 ... 9).contains(sender.tag) else { return }
		digits.append(UInt8(48 + sender.tag))
		refresh()
	}

	@objc private func deleteTapped() {
		guard !digits.isEmpty else { return }
		digits[digits.count - 1] = 0
		digits.removeLast()
		refresh()
	}

	@objc private func confirmTapped() {
		guard digits.count >= BeamioPasscodeRules.minDigits else { return }
		var entered = digits
		BeamioNativeWallet.wipe(&digits)
		let step = runner.submit(entered)
		BeamioNativeWallet.wipe(&entered)
		if let result = step.result {
			finish(result)
			return
		}
		titleLabel.text = copy[step.state.rawValue] ?? copy["title"]
		hintLabel.text = step.message.flatMap { copy[$0] }
		refresh()
	}

	@objc private func cancelTapped() {
		finish(runner.cancel().result ?? .cancelled)
	}

	private func finish(_ result: BeamioPasscodeRunResult) {
		guard !finished else { return }
		finished = true
		BeamioNativeWallet.wipe(&digits)
		onFinish?(result)
		dismiss(animated: true)
	}

	/// The dots show how many digits are entered, never which ones.
	private func refresh() {
		titleLabel.text = titleLabel.text ?? copy["title"]
		if hintLabel.text == nil { hintLabel.text = copy["hint"] }
		for (i, dot) in dotsStack.arrangedSubviews.enumerated() {
			dot.backgroundColor = i < digits.count ? UIColor(passcodeHex: BeamioPasscodeTokens.colors["fg"] ?? "#FFFFFF") : .clear
		}
		confirmButton.isEnabled = digits.count >= BeamioPasscodeRules.minDigits
		confirmButton.alpha = confirmButton.isEnabled ? 1 : 0.4
	}

	/// While the screen is captured or recorded, the input and the dots are hidden.
	@objc private func captureChanged() {
		cover.isHidden = !UIScreen.main.isCaptured
	}
}
#endif
