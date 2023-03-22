defmodule Samly.RouterUtil do
  @moduledoc false

  alias Plug.Conn
  require Logger
  require Samly.Esaml
  alias Samly.{Esaml, IdpData, Helper}

  @subdomain_re ~r/^(?<subdomain>([^.]+))?\./

  def check_idp_id(conn, _opts) do
    Logger.error("#### RouterUtil#check_idp_id")


    idp_id_from = Application.get_env(:samly, :idp_id_from)

    Logger.error("# idp_id_from = #{inspect(idp_id_from)}")
    Logger.error("# conn.params = #{inspect(conn.params)}")

    idp_id =
      if idp_id_from == :subdomain do
        case Regex.named_captures(@subdomain_re, conn.host) do
          %{"subdomain" => idp_id} -> idp_id
          _ -> nil
        end
      else
        case conn.params["idp_id_seg"] do
          [idp_id] -> idp_id
          _ -> nil
        end
      end

    idp = idp_id && Helper.get_idp(idp_id)

    Logger.error("# idp_id = #{inspect(idp_id)}")
    Logger.error("# idp = #{inspect(idp)}")


    if idp do
      conn |> Conn.put_private(:samly_idp, idp)
    else
      conn |> Conn.send_resp(403, "invalid_request unknown IdP") |> Conn.halt()
    end
  end

  def check_target_url(conn, _opts) do
    try do
      target_url = conn.params["target_url"] && URI.decode_www_form(conn.params["target_url"])
      conn |> Conn.put_private(:samly_target_url, target_url)
    rescue
      ArgumentError ->
        Logger.error(
          "[Samly] target_url must be x-www-form-urlencoded: #{inspect(conn.params["target_url"])}"
        )

        conn |> Conn.send_resp(400, "target_url must be x-www-form-urlencoded") |> Conn.halt()
    end
  end

  # generate URIs using the idp_id
  @spec ensure_sp_uris_set(tuple, Conn.t()) :: tuple
  def ensure_sp_uris_set(sp, conn) do
    case Esaml.esaml_sp(sp, :metadata_uri) do
      [?/ | _] ->
        uri = %URI{
          scheme: Atom.to_string(conn.scheme),
          host: conn.host,
          port: conn.port,
          path: "/sso"
        }

        base_url = URI.to_string(uri)
        idp_id_from = Application.get_env(:samly, :idp_id_from)

        path_segment_idp_id =
          if idp_id_from == :subdomain do
            nil
          else
            %IdpData{id: idp_id} = conn.private[:samly_idp]
            idp_id
          end

        Esaml.esaml_sp(
          sp,
          metadata_uri: Helper.get_metadata_uri(base_url, path_segment_idp_id),
          consume_uri: Helper.get_consume_uri(base_url, path_segment_idp_id),
          logout_uri: Helper.get_logout_uri(base_url, path_segment_idp_id)
        )

      _ ->
        sp
    end
  end

  def send_saml_request(conn, idp_url, use_redirect?, signed_xml_payload, relay_state) do
    Logger.error("#### RouterUtil#send_saml_request")
    Logger.error(IO.inspect(Conn.get_session(conn)))
    Logger.error("# idp_url = #{idp_url}")
    Logger.error("# use_redirect? = #{use_redirect?}")
    Logger.error("# relay_state = #{relay_state}")
    Logger.error("# signed_xml_payload = #{inspect(signed_xml_payload)}")


    if use_redirect? do
      url =
        :esaml_binding.encode_http_redirect(idp_url, signed_xml_payload, :undefined, relay_state)

      conn |> redirect(302, url)
    else
      nonce = conn.private[:samly_nonce]
      resp_body = :esaml_binding.encode_http_post(idp_url, signed_xml_payload, relay_state, nonce)

      conn
      |> Conn.put_resp_header("content-type", "text/html")
      |> Conn.send_resp(200, resp_body)
    end
  end

  def redirect(conn, status_code, dest) do
    Logger.error("#### RouterUtil#redirect")
    Logger.error("# dest = #{inspect(dest)}")
    Logger.error("# dest.replace = #{inspect(String.replace(dest, "%25", "%"))}")

    # TODO!!: SAMLResponse の値を URL デコードすればうまくいきそうな気がするが。。
    conn
    |> Conn.put_resp_header("location", dest)
    |> Conn.send_resp(status_code, "")
    |> Conn.halt()
  end
end
