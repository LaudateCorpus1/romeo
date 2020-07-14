defmodule Romeo.Mixfile do
  use Mix.Project

  @version "0.7.1"

  def project do
    [
      app: :romeo,
      name: "Romeo",
      version: @version,
      elixir: "~> 1.1",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: description(),
      deps: deps(),
      docs: docs(),
      package: package(),
      test_coverage: [tool: ExCoveralls]
    ]
  end

  def application do
    [applications: [:logger, :connection, :fast_xml], mod: {Romeo, []}]
  end

  defp description do
    "An XMPP Client for Elixir"
  end

  defp deps do
    [
      {:backoff, "~> 1.1.6"},
      {:connection, "~> 1.0"},
      {:fast_xml, "~> 1.1"},

      # Docs deps
      {:ex_doc, "~> 0.14", only: :dev},

      # Test deps
      {:ejabberd, "~> 16.8", only: :test},
      {:excoveralls, "~> 0.5", only: :test}
    ]
  end

  defp docs do
    [extras: docs_extras(), main: "readme"]
  end

  defp docs_extras do
    ["README.md"]
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Sonny Scroggin"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/scrogson/romeo"}
    ]
  end
end
