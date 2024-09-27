cvss_v3_base_score <- function(cvss_vector) {

  # Define the metric weights based on the CVSS v3.1 specification
  metrics <- list(
    AV = list(N = 0.85, A = 0.62, L = 0.55, P = 0.2),
    AC = list(L = 0.77, H = 0.44),
    PR = list(N_U = 0.85, N_C = 0.85, L_U = 0.62, L_C = 0.68, H_U = 0.27, H_C = 0.5),
    UI = list(N = 0.85, R = 0.62),
    C = list(N = 0, L = 0.22, H = 0.56),
    I = list(N = 0, L = 0.22, H = 0.56),
    A = list(N = 0, L = 0.22, H = 0.56)
  )

  # Check if cvss_vector is a non-empty string
  if (missing(cvss_vector) || !is.character(cvss_vector) || nchar(cvss_vector) == 0) {
    stop("Invalid input: cvss_vector must be a non-empty string.")
  }

  # Parse the CVSS vector
  components <- strsplit(cvss_vector, "/")[[1]]
  values <- list()

  for (component in components) {
    key_value <- strsplit(component, ":")[[1]]

    # Validate the key-value pair
    if (length(key_value) != 2) {
      stop(paste("Invalid component:", component, "- expected format 'KEY:VALUE'."))
    }

    key <- key_value[1]
    value <- key_value[2]

    if (!key %in% names(metrics) && key != "S" && key != "PR") {
      stop(paste("Unknown metric:", key))
    }

    values[[key]] <- value
  }

  # Check for missing required fields
  required_fields <- c("AV", "AC", "PR", "UI", "C", "I", "A", "S")
  missing_fields <- setdiff(required_fields, names(values))
  if (length(missing_fields) > 0) {
    stop(paste("Missing required fields:", paste(missing_fields, collapse = ", ")))
  }

  # Get the appropriate PR value based on the scope
  scope <- values$S
  is_scope_changed <- scope == "C"
  pr_key <- paste(values$PR, ifelse(is_scope_changed, "C", "U"), sep = "_")

  # Check if PR key exists in metrics
  if (!pr_key %in% names(metrics$PR)) {
    stop(paste("Invalid PR value or scope combination:", pr_key))
  }

  # Calculate the ISCBase
  isc_base <- 1 - (1 - metrics$C[[values$C]]) * (1 - metrics$I[[values$I]]) * (1 - metrics$A[[values$A]])

  # Calculate the impact sub-score (ISC)
  impact <- ifelse(
    is_scope_changed,
    7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02)^15,
    6.42 * isc_base
  )

  # Calculate the exploitability sub-score
  exploitability <- 8.22 * metrics$AV[[values$AV]] * metrics$AC[[values$AC]] * metrics$PR[[pr_key]] * metrics$UI[[values$UI]]

  # Calculate the base score based on the scope
  base_score <- if (impact <= 0) {
    0
  } else if (is_scope_changed) {
    min(1.08 * (impact + exploitability), 10)
  } else {
    min(impact + exploitability, 10)
  }

  # Round up the base score to one decimal place
  round_up <- function(x) {
    return(ceiling(x * 10) / 10)
  }

  # Return the base score, rounded up to 1 decimal place
  return(round_up(base_score))

}

cvss_v3_base_scores <- function(cvss_vectors) {

  # Check if cvss_vectors is a non-empty vector of strings
  if (missing(cvss_vectors) || !is.vector(cvss_vectors) || length(cvss_vectors) == 0) {
    stop("Invalid input: cvss_vectors must be a non-empty vector of strings.")
  }

  # Initialize an empty list to store base scores
  base_scores <- list()

  # Loop through each CVSS vector in the list and calculate the base score
  for (cvss_vector in cvss_vectors) {
    base_score <- cvss_v3_base_score(cvss_vector)
    base_scores[[cvss_vector]] <- base_score
  }

  # Return the list of base scores
  return(base_scores)

}
